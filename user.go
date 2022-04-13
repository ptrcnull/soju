package soju

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/SherClockHolmes/webpush-go"
	"gopkg.in/irc.v3"
)

type event interface{}

type eventUpstreamMessage struct {
	msg *irc.Message
	uc  *upstreamConn
}

type eventUpstreamConnectionError struct {
	net *network
	err error
}

type eventUpstreamConnected struct {
	uc *upstreamConn
}

type eventUpstreamDisconnected struct {
	uc *upstreamConn
}

type eventUpstreamError struct {
	uc  *upstreamConn
	err error
}

type eventDownstreamMessage struct {
	msg *irc.Message
	dc  *downstreamConn
}

type eventDownstreamConnected struct {
	dc *downstreamConn
}

type eventDownstreamDisconnected struct {
	dc *downstreamConn
}

type eventChannelDetach struct {
	uc   *upstreamConn
	name string
}

type eventBroadcast struct {
	msg *irc.Message
}

type eventStop struct{}

type eventUserUpdate struct {
	password *string
	admin    *bool
	done     chan error
}

type deliveredClientMap map[string]string // client name -> msg ID

type deliveredStore struct {
	m deliveredCasemapMap
}

func newDeliveredStore() deliveredStore {
	return deliveredStore{deliveredCasemapMap{newCasemapMap(0)}}
}

func (ds deliveredStore) HasTarget(target string) bool {
	return ds.m.Value(target) != nil
}

func (ds deliveredStore) LoadID(target, clientName string) string {
	clients := ds.m.Value(target)
	if clients == nil {
		return ""
	}
	return clients[clientName]
}

func (ds deliveredStore) StoreID(target, clientName, msgID string) {
	clients := ds.m.Value(target)
	if clients == nil {
		clients = make(deliveredClientMap)
		ds.m.SetValue(target, clients)
	}
	clients[clientName] = msgID
}

func (ds deliveredStore) ForEachTarget(f func(target string)) {
	for _, entry := range ds.m.innerMap {
		f(entry.originalKey)
	}
}

func (ds deliveredStore) ForEachClient(f func(clientName string)) {
	clients := make(map[string]struct{})
	for _, entry := range ds.m.innerMap {
		delivered := entry.value.(deliveredClientMap)
		for clientName := range delivered {
			clients[clientName] = struct{}{}
		}
	}

	for clientName := range clients {
		f(clientName)
	}
}

type network struct {
	Network
	user    *user
	logger  Logger
	stopped chan struct{}

	conn      *upstreamConn
	channels  channelCasemapMap
	delivered deliveredStore
	lastError error
	casemap   casemapping
}

func newNetwork(user *user, record *Network, channels []Channel) *network {
	logger := &prefixLogger{user.logger, fmt.Sprintf("network %q: ", record.GetName())}

	m := channelCasemapMap{newCasemapMap(0)}
	for _, ch := range channels {
		ch := ch
		m.SetValue(ch.Name, &ch)
	}

	return &network{
		Network:   *record,
		user:      user,
		logger:    logger,
		stopped:   make(chan struct{}),
		channels:  m,
		delivered: newDeliveredStore(),
		casemap:   casemapRFC1459,
	}
}

func (net *network) forEachDownstream(f func(*downstreamConn)) {
	net.user.forEachDownstream(func(dc *downstreamConn) {
		if dc.network == nil && !dc.isMultiUpstream {
			return
		}
		if dc.network != nil && dc.network != net {
			return
		}
		f(dc)
	})
}

func (net *network) isStopped() bool {
	select {
	case <-net.stopped:
		return true
	default:
		return false
	}
}

func userIdent(u *User) string {
	// The ident is a string we will send to upstream servers in clear-text.
	// For privacy reasons, make sure it doesn't expose any meaningful user
	// metadata. We just use the base64-encoded hashed ID, so that people don't
	// start relying on the string being an integer or following a pattern.
	var b [64]byte
	binary.LittleEndian.PutUint64(b[:], uint64(u.ID))
	h := sha256.Sum256(b[:])
	return hex.EncodeToString(h[:16])
}

func (net *network) run() {
	if !net.Enabled {
		return
	}

	var lastTry time.Time
	backoff := newBackoffer(retryConnectMinDelay, retryConnectMaxDelay, retryConnectJitter)
	for {
		if net.isStopped() {
			return
		}

		delay := backoff.Next() - time.Now().Sub(lastTry)
		if delay > 0 {
			net.logger.Printf("waiting %v before trying to reconnect to %q", delay.Truncate(time.Second), net.Addr)
			time.Sleep(delay)
		}
		lastTry = time.Now()

		net.user.srv.metrics.upstreams.Add(1)

		uc, err := connectToUpstream(context.TODO(), net)
		if err != nil {
			net.logger.Printf("failed to connect to upstream server %q: %v", net.Addr, err)
			net.user.events <- eventUpstreamConnectionError{net, fmt.Errorf("failed to connect: %v", err)}
			net.user.srv.metrics.upstreams.Add(-1)
			net.user.srv.metrics.upstreamConnectErrorsTotal.Inc()
			continue
		}

		if net.user.srv.Identd != nil {
			net.user.srv.Identd.Store(uc.RemoteAddr().String(), uc.LocalAddr().String(), userIdent(&net.user.User))
		}

		uc.register(context.TODO())
		if err := uc.runUntilRegistered(context.TODO()); err != nil {
			text := err.Error()
			temp := true
			if regErr, ok := err.(registrationError); ok {
				text = regErr.Reason()
				temp = regErr.Temporary()
			}
			uc.logger.Printf("failed to register: %v", text)
			net.user.events <- eventUpstreamConnectionError{net, fmt.Errorf("failed to register: %v", text)}
			uc.Close()
			net.user.srv.metrics.upstreams.Add(-1)
			net.user.srv.metrics.upstreamConnectErrorsTotal.Inc()
			if !temp {
				return
			}
			continue
		}

		// TODO: this is racy with net.stopped. If the network is stopped
		// before the user goroutine receives eventUpstreamConnected, the
		// connection won't be closed.
		net.user.events <- eventUpstreamConnected{uc}
		if err := uc.readMessages(net.user.events); err != nil {
			uc.logger.Printf("failed to handle messages: %v", err)
			net.user.events <- eventUpstreamError{uc, fmt.Errorf("failed to handle messages: %v", err)}
		}
		uc.Close()
		net.user.events <- eventUpstreamDisconnected{uc}

		if net.user.srv.Identd != nil {
			net.user.srv.Identd.Delete(uc.RemoteAddr().String(), uc.LocalAddr().String())
		}

		net.user.srv.metrics.upstreams.Add(-1)
		backoff.Reset()
	}
}

func (net *network) stop() {
	if !net.isStopped() {
		close(net.stopped)
	}

	if net.conn != nil {
		net.conn.Close()
	}
}

func (net *network) detach(ch *Channel) {
	if ch.Detached {
		return
	}

	net.logger.Printf("detaching channel %q", ch.Name)

	ch.Detached = true

	if net.user.msgStore != nil {
		nameCM := net.casemap(ch.Name)
		lastID, err := net.user.msgStore.LastMsgID(&net.Network, nameCM, time.Now())
		if err != nil {
			net.logger.Printf("failed to get last message ID for channel %q: %v", ch.Name, err)
		}
		ch.DetachedInternalMsgID = lastID
	}

	if net.conn != nil {
		uch := net.conn.channels.Value(ch.Name)
		if uch != nil {
			uch.updateAutoDetach(0)
		}
	}

	net.forEachDownstream(func(dc *downstreamConn) {
		dc.SendMessage(&irc.Message{
			Prefix:  dc.prefix(),
			Command: "PART",
			Params:  []string{dc.marshalEntity(net, ch.Name), "Detach"},
		})
	})
}

func (net *network) attach(ctx context.Context, ch *Channel) {
	if !ch.Detached {
		return
	}

	net.logger.Printf("attaching channel %q", ch.Name)

	detachedMsgID := ch.DetachedInternalMsgID
	ch.Detached = false
	ch.DetachedInternalMsgID = ""

	var uch *upstreamChannel
	if net.conn != nil {
		uch = net.conn.channels.Value(ch.Name)

		net.conn.updateChannelAutoDetach(ch.Name)
	}

	net.forEachDownstream(func(dc *downstreamConn) {
		dc.SendMessage(&irc.Message{
			Prefix:  dc.prefix(),
			Command: "JOIN",
			Params:  []string{dc.marshalEntity(net, ch.Name)},
		})

		if uch != nil {
			forwardChannel(ctx, dc, uch)
		}

		if detachedMsgID != "" {
			dc.sendTargetBacklog(ctx, net, ch.Name, detachedMsgID)
		}
	})
}

func (net *network) deleteChannel(ctx context.Context, name string) error {
	ch := net.channels.Value(name)
	if ch == nil {
		return fmt.Errorf("unknown channel %q", name)
	}
	if net.conn != nil {
		uch := net.conn.channels.Value(ch.Name)
		if uch != nil {
			uch.updateAutoDetach(0)
		}
	}

	if err := net.user.srv.db.DeleteChannel(ctx, ch.ID); err != nil {
		return err
	}
	net.channels.Delete(name)
	return nil
}

func (net *network) updateCasemapping(newCasemap casemapping) {
	net.casemap = newCasemap
	net.channels.SetCasemapping(newCasemap)
	net.delivered.m.SetCasemapping(newCasemap)
	if uc := net.conn; uc != nil {
		uc.channels.SetCasemapping(newCasemap)
		for _, entry := range uc.channels.innerMap {
			uch := entry.value.(*upstreamChannel)
			uch.Members.SetCasemapping(newCasemap)
		}
		uc.monitored.SetCasemapping(newCasemap)
	}
	net.forEachDownstream(func(dc *downstreamConn) {
		dc.monitored.SetCasemapping(newCasemap)
	})
}

func (net *network) storeClientDeliveryReceipts(ctx context.Context, clientName string) {
	if !net.user.hasPersistentMsgStore() {
		return
	}

	var receipts []DeliveryReceipt
	net.delivered.ForEachTarget(func(target string) {
		msgID := net.delivered.LoadID(target, clientName)
		if msgID == "" {
			return
		}
		receipts = append(receipts, DeliveryReceipt{
			Target:        target,
			InternalMsgID: msgID,
		})
	})

	if err := net.user.srv.db.StoreClientDeliveryReceipts(ctx, net.ID, clientName, receipts); err != nil {
		net.logger.Printf("failed to store delivery receipts for client %q: %v", clientName, err)
	}
}

func (net *network) isHighlight(msg *irc.Message) bool {
	if msg.Command != "PRIVMSG" && msg.Command != "NOTICE" {
		return false
	}

	text := msg.Params[1]

	nick := net.Nick
	if net.conn != nil {
		nick = net.conn.nick
	}

	// TODO: use case-mapping aware comparison here
	return msg.Prefix.Name != nick && isHighlight(text, nick)
}

func (net *network) detachedMessageNeedsRelay(ch *Channel, msg *irc.Message) bool {
	highlight := net.isHighlight(msg)
	return ch.RelayDetached == FilterMessage || ((ch.RelayDetached == FilterHighlight || ch.RelayDetached == FilterDefault) && highlight)
}

func (net *network) autoSaveSASLPlain(ctx context.Context, username, password string) {
	// User may have e.g. EXTERNAL mechanism configured. We do not want to
	// automatically erase the key pair or any other credentials.
	if net.SASL.Mechanism != "" && net.SASL.Mechanism != "PLAIN" {
		return
	}

	net.logger.Printf("auto-saving SASL PLAIN credentials with username %q", username)
	net.SASL.Mechanism = "PLAIN"
	net.SASL.Plain.Username = username
	net.SASL.Plain.Password = password
	if err := net.user.srv.db.StoreNetwork(ctx, net.user.ID, &net.Network); err != nil {
		net.logger.Printf("failed to save SASL PLAIN credentials: %v", err)
	}
}

func (net *network) broadcastWebPush(ctx context.Context, msg *irc.Message) {
	subs, err := net.user.srv.db.ListWebPushSubscriptions(ctx, net.ID)
	if err != nil {
		net.logger.Printf("failed to list Web push subscriptions: %v", err)
		return
	}

	for _, sub := range subs {
		err := net.user.srv.sendWebPush(ctx, &webpush.Subscription{
			Endpoint: sub.Endpoint,
			Keys: webpush.Keys{
				Auth:   sub.Keys.Auth,
				P256dh: sub.Keys.P256DH,
			},
		}, sub.Keys.VAPID, msg)
		if err != nil {
			net.logger.Printf("failed to send Web push notification to endpoint %q: %v", sub.Endpoint, err)
		}
		if err == errWebPushSubscriptionExpired {
			if err := net.user.srv.db.DeleteWebPushSubscription(ctx, sub.ID); err != nil {
				net.logger.Printf("failed to delete expired Web Push subscription: %v", err)
			}
		}
	}
}

type user struct {
	User
	srv    *Server
	logger Logger

	events chan event
	done   chan struct{}

	networks        []*network
	downstreamConns []*downstreamConn
	msgStore        messageStore
}

func newUser(srv *Server, record *User) *user {
	logger := &prefixLogger{srv.Logger, fmt.Sprintf("user %q: ", record.Username)}

	var msgStore messageStore
	if logPath := srv.Config().LogPath; logPath != "" {
		msgStore = newFSMessageStore(logPath, record)
	} else {
		msgStore = newMemoryMessageStore()
	}

	return &user{
		User:     *record,
		srv:      srv,
		logger:   logger,
		events:   make(chan event, 64),
		done:     make(chan struct{}),
		msgStore: msgStore,
	}
}

func (u *user) forEachUpstream(f func(uc *upstreamConn)) {
	for _, network := range u.networks {
		if network.conn == nil {
			continue
		}
		f(network.conn)
	}
}

func (u *user) forEachDownstream(f func(dc *downstreamConn)) {
	for _, dc := range u.downstreamConns {
		f(dc)
	}
}

func (u *user) getNetwork(name string) *network {
	for _, network := range u.networks {
		if network.Addr == name {
			return network
		}
		if network.Name != "" && network.Name == name {
			return network
		}
	}
	return nil
}

func (u *user) getNetworkByID(id int64) *network {
	for _, net := range u.networks {
		if net.ID == id {
			return net
		}
	}
	return nil
}

func (u *user) run() {
	defer func() {
		if u.msgStore != nil {
			if err := u.msgStore.Close(); err != nil {
				u.logger.Printf("failed to close message store for user %q: %v", u.Username, err)
			}
		}
		close(u.done)
	}()

	networks, err := u.srv.db.ListNetworks(context.TODO(), u.ID)
	if err != nil {
		u.logger.Printf("failed to list networks for user %q: %v", u.Username, err)
		return
	}

	sort.Slice(networks, func(i, j int) bool {
		return networks[i].ID < networks[j].ID
	})

	for _, record := range networks {
		record := record
		channels, err := u.srv.db.ListChannels(context.TODO(), record.ID)
		if err != nil {
			u.logger.Printf("failed to list channels for user %q, network %q: %v", u.Username, record.GetName(), err)
			continue
		}

		network := newNetwork(u, &record, channels)
		u.networks = append(u.networks, network)

		if u.hasPersistentMsgStore() {
			receipts, err := u.srv.db.ListDeliveryReceipts(context.TODO(), record.ID)
			if err != nil {
				u.logger.Printf("failed to load delivery receipts for user %q, network %q: %v", u.Username, network.GetName(), err)
				return
			}

			for _, rcpt := range receipts {
				network.delivered.StoreID(rcpt.Target, rcpt.Client, rcpt.InternalMsgID)
			}
		}

		go network.run()
	}

	for e := range u.events {
		switch e := e.(type) {
		case eventUpstreamConnected:
			uc := e.uc

			uc.network.conn = uc

			uc.updateAway()
			uc.updateMonitor()

			netIDStr := fmt.Sprintf("%v", uc.network.ID)
			uc.forEachDownstream(func(dc *downstreamConn) {
				dc.updateSupportedCaps()

				if !dc.caps.IsEnabled("soju.im/bouncer-networks") {
					sendServiceNOTICE(dc, fmt.Sprintf("connected to %s", uc.network.GetName()))
				}

				dc.updateNick()
				dc.updateHost()
				dc.updateRealname()
				dc.updateAccount()
			})
			u.forEachDownstream(func(dc *downstreamConn) {
				if dc.caps.IsEnabled("soju.im/bouncer-networks-notify") {
					dc.SendMessage(&irc.Message{
						Prefix:  dc.srv.prefix(),
						Command: "BOUNCER",
						Params: []string{"NETWORK", netIDStr, irc.Tags{
							"state": "connected",
							"error": "",
						}.String()},
					})
				}
			})
			uc.network.lastError = nil
		case eventUpstreamDisconnected:
			u.handleUpstreamDisconnected(e.uc)
		case eventUpstreamConnectionError:
			net := e.net

			stopped := false
			select {
			case <-net.stopped:
				stopped = true
			default:
			}

			if !stopped && (net.lastError == nil || net.lastError.Error() != e.err.Error()) {
				net.forEachDownstream(func(dc *downstreamConn) {
					sendServiceNOTICE(dc, fmt.Sprintf("failed connecting/registering to %s: %v", net.GetName(), e.err))
				})
			}
			net.lastError = e.err
			u.forEachDownstream(func(dc *downstreamConn) {
				if dc.caps.IsEnabled("soju.im/bouncer-networks-notify") {
					dc.SendMessage(&irc.Message{
						Prefix:  dc.srv.prefix(),
						Command: "BOUNCER",
						Params: []string{"NETWORK", fmt.Sprintf("%v", net.ID), irc.Tags{
							"error": irc.TagValue(net.lastError.Error()),
						}.String()},
					})
				}
			})
		case eventUpstreamError:
			uc := e.uc

			uc.forEachDownstream(func(dc *downstreamConn) {
				sendServiceNOTICE(dc, fmt.Sprintf("disconnected from %s: %v", uc.network.GetName(), e.err))
			})
			uc.network.lastError = e.err
			u.forEachDownstream(func(dc *downstreamConn) {
				if dc.caps.IsEnabled("soju.im/bouncer-networks-notify") {
					dc.SendMessage(&irc.Message{
						Prefix:  dc.srv.prefix(),
						Command: "BOUNCER",
						Params: []string{"NETWORK", fmt.Sprintf("%v", uc.network.ID), irc.Tags{
							"error": irc.TagValue(uc.network.lastError.Error()),
						}.String()},
					})
				}
			})
		case eventUpstreamMessage:
			msg, uc := e.msg, e.uc
			if uc.isClosed() {
				uc.logger.Printf("ignoring message on closed connection: %v", msg)
				break
			}
			if err := uc.handleMessage(context.TODO(), msg); err != nil {
				uc.logger.Printf("failed to handle message %q: %v", msg, err)
			}
		case eventChannelDetach:
			uc, name := e.uc, e.name
			c := uc.network.channels.Value(name)
			if c == nil || c.Detached {
				continue
			}
			uc.network.detach(c)
			if err := uc.srv.db.StoreChannel(context.TODO(), uc.network.ID, c); err != nil {
				u.logger.Printf("failed to store updated detached channel %q: %v", c.Name, err)
			}
		case eventDownstreamConnected:
			dc := e.dc

			if dc.network != nil {
				dc.monitored.SetCasemapping(dc.network.casemap)
			}

			if err := dc.welcome(context.TODO()); err != nil {
				if ircErr, ok := err.(ircError); ok {
					msg := ircErr.Message.Copy()
					msg.Prefix = dc.srv.prefix()
					dc.SendMessage(msg)
				} else {
					dc.SendMessage(&irc.Message{
						Command: "ERROR",
						Params:  []string{"Internal server error"},
					})
				}
				dc.logger.Printf("failed to handle new registered connection: %v", err)
				// TODO: close dc after the error message is sent
				break
			}

			u.downstreamConns = append(u.downstreamConns, dc)

			dc.forEachNetwork(func(network *network) {
				if network.lastError != nil {
					sendServiceNOTICE(dc, fmt.Sprintf("disconnected from %s: %v", network.GetName(), network.lastError))
				}
			})

			u.forEachUpstream(func(uc *upstreamConn) {
				uc.updateAway()
			})
		case eventDownstreamDisconnected:
			dc := e.dc

			for i := range u.downstreamConns {
				if u.downstreamConns[i] == dc {
					u.downstreamConns = append(u.downstreamConns[:i], u.downstreamConns[i+1:]...)
					break
				}
			}

			dc.forEachNetwork(func(net *network) {
				net.storeClientDeliveryReceipts(context.TODO(), dc.clientName)
			})

			u.forEachUpstream(func(uc *upstreamConn) {
				uc.cancelPendingCommandsByDownstreamID(dc.id)
				uc.updateAway()
				uc.updateMonitor()
			})
		case eventDownstreamMessage:
			msg, dc := e.msg, e.dc
			if dc.isClosed() {
				dc.logger.Printf("ignoring message on closed connection: %v", msg)
				break
			}
			err := dc.handleMessage(context.TODO(), msg)
			if ircErr, ok := err.(ircError); ok {
				ircErr.Message.Prefix = dc.srv.prefix()
				dc.SendMessage(ircErr.Message)
			} else if err != nil {
				dc.logger.Printf("failed to handle message %q: %v", msg, err)
				dc.Close()
			}
		case eventBroadcast:
			msg := e.msg
			u.forEachDownstream(func(dc *downstreamConn) {
				dc.SendMessage(msg)
			})
		case eventUserUpdate:
			// copy the user record because we'll mutate it
			record := u.User

			if e.password != nil {
				record.Password = *e.password
			}
			if e.admin != nil {
				record.Admin = *e.admin
			}

			e.done <- u.updateUser(context.TODO(), &record)

			// If the password was updated, kill all downstream connections to
			// force them to re-authenticate with the new credentials.
			if e.password != nil {
				u.forEachDownstream(func(dc *downstreamConn) {
					dc.Close()
				})
			}
		case eventStop:
			u.forEachDownstream(func(dc *downstreamConn) {
				dc.Close()
			})
			for _, n := range u.networks {
				n.stop()

				n.delivered.ForEachClient(func(clientName string) {
					n.storeClientDeliveryReceipts(context.TODO(), clientName)
				})
			}
			return
		default:
			panic(fmt.Sprintf("received unknown event type: %T", e))
		}
	}
}

func (u *user) handleUpstreamDisconnected(uc *upstreamConn) {
	uc.network.conn = nil

	uc.abortPendingCommands()

	for _, entry := range uc.channels.innerMap {
		uch := entry.value.(*upstreamChannel)
		uch.updateAutoDetach(0)
	}

	netIDStr := fmt.Sprintf("%v", uc.network.ID)
	uc.forEachDownstream(func(dc *downstreamConn) {
		dc.updateSupportedCaps()
	})

	// If the network has been removed, don't send a state change notification
	found := false
	for _, net := range u.networks {
		if net == uc.network {
			found = true
			break
		}
	}
	if !found {
		return
	}

	u.forEachDownstream(func(dc *downstreamConn) {
		if dc.caps.IsEnabled("soju.im/bouncer-networks-notify") {
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: "BOUNCER",
				Params:  []string{"NETWORK", netIDStr, "state=disconnected"},
			})
		}
	})

	if uc.network.lastError == nil {
		uc.forEachDownstream(func(dc *downstreamConn) {
			if !dc.caps.IsEnabled("soju.im/bouncer-networks") {
				sendServiceNOTICE(dc, fmt.Sprintf("disconnected from %s", uc.network.GetName()))
			}
		})
	}
}

func (u *user) addNetwork(network *network) {
	u.networks = append(u.networks, network)

	sort.Slice(u.networks, func(i, j int) bool {
		return u.networks[i].ID < u.networks[j].ID
	})

	go network.run()
}

func (u *user) removeNetwork(network *network) {
	network.stop()

	u.forEachDownstream(func(dc *downstreamConn) {
		if dc.network != nil && dc.network == network {
			dc.Close()
		}
	})

	for i, net := range u.networks {
		if net == network {
			u.networks = append(u.networks[:i], u.networks[i+1:]...)
			return
		}
	}

	panic("tried to remove a non-existing network")
}

func (u *user) checkNetwork(record *Network) error {
	url, err := record.URL()
	if err != nil {
		return err
	}
	if url.User != nil {
		return fmt.Errorf("%v:// URL must not have username and password information", url.Scheme)
	}
	if url.RawQuery != "" {
		return fmt.Errorf("%v:// URL must not have query values", url.Scheme)
	}
	if url.Fragment != "" {
		return fmt.Errorf("%v:// URL must not have a fragment", url.Scheme)
	}
	switch url.Scheme {
	case "ircs", "irc+insecure":
		if url.Host == "" {
			return fmt.Errorf("%v:// URL must have a host", url.Scheme)
		}
		if url.Path != "" {
			return fmt.Errorf("%v:// URL must not have a path", url.Scheme)
		}
	case "irc+unix", "unix":
		if url.Host != "" {
			return fmt.Errorf("%v:// URL must not have a host", url.Scheme)
		}
		if url.Path == "" {
			return fmt.Errorf("%v:// URL must have a path", url.Scheme)
		}
	default:
		return fmt.Errorf("unknown URL scheme %q", url.Scheme)
	}

	if record.GetName() == "" {
		return fmt.Errorf("network name cannot be empty")
	}
	if strings.HasPrefix(record.GetName(), "-") {
		// Can be mixed up with flags when sending commands to the service
		return fmt.Errorf("network name cannot start with a dash character")
	}

	for _, net := range u.networks {
		if net.GetName() == record.GetName() && net.ID != record.ID {
			return fmt.Errorf("a network with the name %q already exists", record.GetName())
		}
	}

	return nil
}

func (u *user) createNetwork(ctx context.Context, record *Network) (*network, error) {
	if record.ID != 0 {
		panic("tried creating an already-existing network")
	}

	if err := u.checkNetwork(record); err != nil {
		return nil, err
	}

	if max := u.srv.Config().MaxUserNetworks; max >= 0 && len(u.networks) >= max {
		return nil, fmt.Errorf("maximum number of networks reached")
	}

	network := newNetwork(u, record, nil)
	err := u.srv.db.StoreNetwork(ctx, u.ID, &network.Network)
	if err != nil {
		return nil, err
	}

	u.addNetwork(network)

	idStr := fmt.Sprintf("%v", network.ID)
	attrs := getNetworkAttrs(network)
	u.forEachDownstream(func(dc *downstreamConn) {
		if dc.caps.IsEnabled("soju.im/bouncer-networks-notify") {
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: "BOUNCER",
				Params:  []string{"NETWORK", idStr, attrs.String()},
			})
		}
	})

	return network, nil
}

func (u *user) updateNetwork(ctx context.Context, record *Network) (*network, error) {
	if record.ID == 0 {
		panic("tried updating a new network")
	}

	// If the realname is reset to the default, just wipe the per-network
	// setting
	if record.Realname == u.Realname {
		record.Realname = ""
	}

	if err := u.checkNetwork(record); err != nil {
		return nil, err
	}

	network := u.getNetworkByID(record.ID)
	if network == nil {
		panic("tried updating a non-existing network")
	}

	if err := u.srv.db.StoreNetwork(ctx, u.ID, record); err != nil {
		return nil, err
	}

	// Most network changes require us to re-connect to the upstream server

	channels := make([]Channel, 0, network.channels.Len())
	for _, entry := range network.channels.innerMap {
		ch := entry.value.(*Channel)
		channels = append(channels, *ch)
	}

	updatedNetwork := newNetwork(u, record, channels)

	// If we're currently connected, disconnect and perform the necessary
	// bookkeeping
	if network.conn != nil {
		network.stop()
		// Note: this will set network.conn to nil
		u.handleUpstreamDisconnected(network.conn)
	}

	// Patch downstream connections to use our fresh updated network
	u.forEachDownstream(func(dc *downstreamConn) {
		if dc.network != nil && dc.network == network {
			dc.network = updatedNetwork
		}
	})

	// We need to remove the network after patching downstream connections,
	// otherwise they'll get closed
	u.removeNetwork(network)

	// The filesystem message store needs to be notified whenever the network
	// is renamed
	fsMsgStore, isFS := u.msgStore.(*fsMessageStore)
	if isFS && updatedNetwork.GetName() != network.GetName() {
		if err := fsMsgStore.RenameNetwork(&network.Network, &updatedNetwork.Network); err != nil {
			network.logger.Printf("failed to update FS message store network name to %q: %v", updatedNetwork.GetName(), err)
		}
	}

	// This will re-connect to the upstream server
	u.addNetwork(updatedNetwork)

	// TODO: only broadcast attributes that have changed
	idStr := fmt.Sprintf("%v", updatedNetwork.ID)
	attrs := getNetworkAttrs(updatedNetwork)
	u.forEachDownstream(func(dc *downstreamConn) {
		if dc.caps.IsEnabled("soju.im/bouncer-networks-notify") {
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: "BOUNCER",
				Params:  []string{"NETWORK", idStr, attrs.String()},
			})
		}
	})

	return updatedNetwork, nil
}

func (u *user) deleteNetwork(ctx context.Context, id int64) error {
	network := u.getNetworkByID(id)
	if network == nil {
		panic("tried deleting a non-existing network")
	}

	if err := u.srv.db.DeleteNetwork(ctx, network.ID); err != nil {
		return err
	}

	u.removeNetwork(network)

	idStr := fmt.Sprintf("%v", network.ID)
	u.forEachDownstream(func(dc *downstreamConn) {
		if dc.caps.IsEnabled("soju.im/bouncer-networks-notify") {
			dc.SendMessage(&irc.Message{
				Prefix:  dc.srv.prefix(),
				Command: "BOUNCER",
				Params:  []string{"NETWORK", idStr, "*"},
			})
		}
	})

	return nil
}

func (u *user) updateUser(ctx context.Context, record *User) error {
	if u.ID != record.ID {
		panic("ID mismatch when updating user")
	}

	realnameUpdated := u.Realname != record.Realname
	if err := u.srv.db.StoreUser(ctx, record); err != nil {
		return fmt.Errorf("failed to update user %q: %v", u.Username, err)
	}
	u.User = *record

	if realnameUpdated {
		// Re-connect to networks which use the default realname
		var needUpdate []Network
		for _, net := range u.networks {
			if net.Realname != "" {
				continue
			}

			// We only need to call updateNetwork for upstreams that don't
			// support setname
			if uc := net.conn; uc != nil && uc.caps.IsEnabled("setname") {
				uc.SendMessage(ctx, &irc.Message{
					Command: "SETNAME",
					Params:  []string{GetRealname(&u.User, &net.Network)},
				})
				continue
			}

			needUpdate = append(needUpdate, net.Network)
		}

		var netErr error
		for _, net := range needUpdate {
			if _, err := u.updateNetwork(ctx, &net); err != nil {
				netErr = err
			}
		}
		if netErr != nil {
			return netErr
		}
	}

	return nil
}

func (u *user) stop() {
	u.events <- eventStop{}
	<-u.done
}

func (u *user) hasPersistentMsgStore() bool {
	if u.msgStore == nil {
		return false
	}
	_, isMem := u.msgStore.(*memoryMessageStore)
	return !isMem
}

// localAddrForHost returns the local address to use when connecting to host.
// A nil address is returned when the OS should automatically pick one.
func (u *user) localTCPAddrForHost(ctx context.Context, host string) (*net.TCPAddr, error) {
	upstreamUserIPs := u.srv.Config().UpstreamUserIPs
	if len(upstreamUserIPs) == 0 {
		return nil, nil
	}

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}

	wantIPv6 := false
	for _, ip := range ips {
		if ip.To4() == nil {
			wantIPv6 = true
			break
		}
	}

	var ipNet *net.IPNet
	for _, in := range upstreamUserIPs {
		if wantIPv6 == (in.IP.To4() == nil) {
			ipNet = in
			break
		}
	}
	if ipNet == nil {
		return nil, nil
	}

	var ipInt big.Int
	ipInt.SetBytes(ipNet.IP)
	ipInt.Add(&ipInt, big.NewInt(u.ID+1))
	ip := net.IP(ipInt.Bytes())
	if !ipNet.Contains(ip) {
		return nil, fmt.Errorf("IP network %v too small", ipNet)
	}

	return &net.TCPAddr{IP: ip}, nil
}
