package ros

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fetchrobotics/rosgo/xmlrpc"
)

const (
	APIStatusError   = -1
	APIStatusFailure = 0
	APIStatusSuccess = 1
	Remap            = ":="
)

func processArguments(args []string) (NameMap, NameMap, NameMap, []string) {
	mapping := make(NameMap)
	params := make(NameMap)
	specials := make(NameMap)
	rest := make([]string, 0)
	for _, arg := range args {
		components := strings.Split(arg, Remap)
		if len(components) == 2 {
			key := components[0]
			value := components[1]
			if strings.HasPrefix(key, "__") {
				specials[key] = value
			} else if strings.HasPrefix(key, "_") {
				params[key[1:]] = value
			} else {
				mapping[key] = value
			}
		} else {
			rest = append(rest, arg)
		}
	}
	return mapping, params, specials, rest
}

// *defaultNode implements Node interface
// a defaultNode instance must be accessed in user goroutine.
type defaultNode struct {
	name           string
	namespace      string
	qualifiedName  string
	masterURI      string
	xmlrpcURI      string
	xmlrpcListener net.Listener
	xmlrpcHandler  *xmlrpc.Handler
	subscribers    map[string]*defaultSubscriber
	publishers     sync.Map
	servers        map[string]*defaultServiceServer
	jobChan        chan func()
	interruptChan  chan os.Signal
	logger         Logger
	ok             bool
	okMutex        sync.RWMutex
	waitGroup      sync.WaitGroup
	logDir         string
	hostname       string
	listenIP       string
	homeDir        string
	nameResolver   *NameResolver
	nonRosArgs     []string
}

func newDefaultNode(name string, args []string) (*defaultNode, error) {
	node := new(defaultNode)

	namespace, nodeName, err := qualifyNodeName(name)
	if err != nil {
		return nil, err
	}

	remapping, params, specials, rest := processArguments(args)

	node.homeDir = filepath.Join(os.Getenv("HOME"), ".ros")
	if homeDir := os.Getenv("ROS_HOME"); len(homeDir) > 0 {
		node.homeDir = homeDir
	}

	node.name = nodeName
	if value, ok := specials["__name"]; ok {
		node.name = value
	}

	node.namespace = namespace
	if ns := os.Getenv("ROS_NAMESPACE"); len(ns) > 0 {
		node.namespace = ns
	}
	if value, ok := specials["__ns"]; ok {
		node.namespace = value
	}
	node.logDir = filepath.Join(node.homeDir, "log")
	if logDir := os.Getenv("ROS_LOG_DIR"); len(logDir) > 0 {
		node.logDir = logDir
	}
	if value, ok := specials["__log"]; ok {
		node.logDir = value
	}

	var onlyLocalhost bool
	node.hostname, onlyLocalhost = determineHost()
	if value, ok := specials["__hostname"]; ok {
		node.hostname = value
		onlyLocalhost = (value == "localhost")
	} else if value, ok := specials["__ip"]; ok {
		node.hostname = value
		onlyLocalhost = (value == "::1" || strings.HasPrefix(value, "127."))
	}
	if onlyLocalhost {
		node.listenIP = "127.0.0.1"
	} else {
		node.listenIP = "0.0.0.0"
	}

	node.masterURI = os.Getenv("ROS_MASTER_URI")
	if value, ok := specials["__master"]; ok {
		node.masterURI = value
	}

	node.nameResolver = newNameResolver(node.namespace, node.name, remapping)
	node.nonRosArgs = rest

	node.qualifiedName = node.namespace + "/" + node.name
	if len(node.namespace) == 1 {
		node.qualifiedName = node.namespace + node.name
	}

	node.subscribers = make(map[string]*defaultSubscriber)
	node.servers = make(map[string]*defaultServiceServer)
	node.interruptChan = make(chan os.Signal)
	node.ok = true

	logger := NewDefaultLogger()
	node.logger = logger

	// Install signal handler
	signal.Notify(node.interruptChan, os.Interrupt)
	go func() {
		<-node.interruptChan
		logger.Info("Interrupted")
		node.okMutex.Lock()
		node.ok = false
		node.okMutex.Unlock()
	}()

	node.jobChan = make(chan func(), 100)

	logger.Debugf("Master URI = %s", node.masterURI)

	// Set parameters set by arguments
	for k, v := range params {
		_, err := callRosAPI(node.masterURI, "setParam", node.qualifiedName, k, v)
		if err != nil {
			return nil, err
		}
	}

	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		logger.Fatal(err)
		return nil, err
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		// Not reached
		panic(err)
	}
	node.xmlrpcURI = fmt.Sprintf("http://%s:%s", node.hostname, port)
	logger.Debugf("listen on http://%s", listener.Addr().String())
	node.xmlrpcListener = listener
	m := map[string]xmlrpc.Method{
		"getBusStats":      func(callerID string) (interface{}, error) { return node.getBusStats(callerID) },
		"getBusInfo":       func(callerID string) (interface{}, error) { return node.getBusInfo(callerID) },
		"getMasterUri":     func(callerID string) (interface{}, error) { return node.getmasterURI(callerID) },
		"shutdown":         func(callerID string, msg string) (interface{}, error) { return node.shutdown(callerID, msg) },
		"getPid":           func(callerID string) (interface{}, error) { return node.getPid(callerID) },
		"getSubscriptions": func(callerID string) (interface{}, error) { return node.getSubscriptions(callerID) },
		"getPublications":  func(callerID string) (interface{}, error) { return node.getPublications(callerID) },
		"paramUpdate": func(callerID string, key string, value interface{}) (interface{}, error) {
			return node.paramUpdate(callerID, key, value)
		},
		"publisherUpdate": func(callerID string, topic string, publishers []interface{}) (interface{}, error) {
			return node.publisherUpdate(callerID, topic, publishers)
		},
		"requestTopic": func(callerID string, topic string, protocols []interface{}) (interface{}, error) {
			return node.requestTopic(callerID, topic, protocols)
		},
	}
	node.xmlrpcHandler = xmlrpc.NewHandler(m)
	go http.Serve(node.xmlrpcListener, node.xmlrpcHandler)
	logger.Debugf("Started %s", node.qualifiedName)
	return node, nil
}

func (node *defaultNode) OK() bool {
	node.okMutex.RLock()
	ok := node.ok
	node.okMutex.RUnlock()
	return ok
}

func (node *defaultNode) getBusStats(callerID string) (interface{}, error) {
	publishStats := []interface{}{}
	for t, p := range node.publishers {
		var msgDataSent uint32
		var ps []interface{}
		msgDataSent, ps = p.getPublisherStats()
		pubConnectionData := []interface{}{t, msgDataSent, ps}
		publishStats = append(publishStats, pubConnectionData)
	}

	subscribeStats := []interface{}{}
	for t, s := range node.subscribers {
		subConnectionData := []interface{}{t, s.getSubscriberStats()}
		subscribeStats = append(subscribeStats, subConnectionData)
	}

	serviceStats := []interface{}{}

	stats := []interface{}{publishStats, subscribeStats, serviceStats}
	return buildRosAPIResult(APIStatusSuccess, "bus stats", stats), nil
}

func (node *defaultNode) getBusInfo(callerID string) (interface{}, error) {
	publishInfo := []interface{}{}
	for _, p := range node.publishers {
		publishInfo = append(publishInfo, p.getPublisherInfo()...)
	}

	subscribeInfo := []interface{}{}
	for _, s := range node.subscribers {
		subscribeInfo = append(subscribeInfo, s.getSubscriberInfo()...)
	}

	serviceInfo := []interface{}{}

	info := []interface{}{}
	info = append(info, publishInfo...)
	info = append(info, subscribeInfo...)
	info = append(info, serviceInfo...)

	return buildRosAPIResult(APIStatusSuccess, "bus info", info), nil
}

func (node *defaultNode) getmasterURI(callerID string) (interface{}, error) {
	return buildRosAPIResult(0, "Success", node.masterURI), nil
}

func (node *defaultNode) shutdown(callerID string, msg string) (interface{}, error) {
	node.okMutex.Lock()
	node.ok = false
	node.okMutex.Unlock()
	return buildRosAPIResult(0, "Success", 0), nil
}

func (node *defaultNode) getPid(callerID string) (interface{}, error) {
	return buildRosAPIResult(0, "Success", os.Getpid()), nil
}

func (node *defaultNode) getSubscriptions(callerID string) (interface{}, error) {
	result := []interface{}{}
	for t, s := range node.subscribers {
		pair := []interface{}{t, s.msgType.Name()}
		result = append(result, pair)
	}
	return buildRosAPIResult(0, "Success", result), nil
}

func (node *defaultNode) getPublications(callerID string) (interface{}, error) {
	result := []interface{}{}
	node.publishers.Range(func(t interface{}, p interface{}) bool {
		pair := []interface{}{
			t.(string),
			p.(*defaultPublisher).msgType.Name(),
		}
		result = append(result, pair)
		return true
	})

	return buildRosApiResult(0, "Success", result), nil
}

func (node *defaultNode) paramUpdate(callerID string, key string, value interface{}) (interface{}, error) {
	return buildRosAPIResult(-1, "Not implemented", 0), nil
}

func (node *defaultNode) publisherUpdate(callerID string, topic string, publishers []interface{}) (interface{}, error) {
	node.logger.Debug("Slave API publisherUpdate() called.")
	var code int32
	var message string
	if sub, ok := node.subscribers[topic]; !ok {
		node.logger.Debug("publisherUpdate() called without subscribing topic.")
		code = 0
		message = "No such topic"
	} else {
		pubURIs := make([]string, len(publishers))
		for i, URI := range publishers {
			pubURIs[i] = URI.(string)
		}
		sub.pubListChan <- pubURIs
		code = 1
		message = "Success"
	}
	return buildRosAPIResult(code, message, 0), nil
}

func (node *defaultNode) requestTopic(callerID string, topic string, protocols []interface{}) (interface{}, error) {
	node.logger.Debugf("Slave API requestTopic(%s, %s, ...) called.", callerID, topic)
	var code int32
	var message string
	var value interface{}
	if pub, ok := node.publishers.Load(topic); !ok {
		node.logger.Debug("requestTopic() called with not publishing topic.")
		code = 0
		message = "No such topic"
		value = nil
	} else {
		selectedProtocol := make([]interface{}, 0)
		for _, v := range protocols {
			protocolParams := v.([]interface{})
			protocolName := protocolParams[0].(string)
			if protocolName == "TCPROS" {
				node.logger.Debug("TCPROS requested")
				selectedProtocol = append(selectedProtocol, "TCPROS")
				host, portStr := pub.(*defaultPublisher).hostAndPort()
				p, err := strconv.ParseInt(portStr, 10, 32)
				if err != nil {
					return nil, err
				}
				port := int(p)
				selectedProtocol = append(selectedProtocol, host)
				selectedProtocol = append(selectedProtocol, port)
				break
			}
		}
		node.logger.Debug(selectedProtocol)
		code = 1
		message = "Success"
		value = selectedProtocol
	}
	return buildRosAPIResult(code, message, value), nil
}

func (node *defaultNode) NewPublisher(topic string, msgType MessageType) Publisher {
	name := node.nameResolver.remap(topic)
	return node.NewPublisherWithCallbacks(name, msgType, nil, nil)
}

func (node *defaultNode) NewPublisherWithCallbacks(topic string, msgType MessageType, connectCallback, disconnectCallback func(SingleSubscriberPublisher)) Publisher {
	name := node.nameResolver.remap(topic)
	pub, ok := node.publishers.Load(topic)
	logger := node.logger
	if !ok {
		_, err := callRosAPI(node.masterURI, "registerPublisher",
			node.qualifiedName,
			name, msgType.Name(),
			node.xmlrpcURI)
		if err != nil {
			logger.Fatalf("Failed to call registerPublisher(): %s", err)
		}

		pub = newDefaultPublisher(node, name, msgType, connectCallback, disconnectCallback)
		node.publishers.Store(name, pub)
		go pub.(*defaultPublisher).start(&node.waitGroup)
	}
	return pub.(*defaultPublisher)
}

func (node *defaultNode) NewSubscriber(topic string, msgType MessageType, callback interface{}) Subscriber {
	name := node.nameResolver.remap(topic)
	sub, ok := node.subscribers[name]
	logger := node.logger
	if !ok {
		node.logger.Debug("Call Master API registerSubscriber")
		result, err := callRosAPI(node.masterURI, "registerSubscriber",
			node.qualifiedName,
			name,
			msgType.Name(),
			node.xmlrpcURI)
		if err != nil {
			logger.Fatalf("Failed to call registerSubscriber() for %s.", err)
		}
		list, ok := result.([]interface{})
		if !ok {
			logger.Fatalf("result is not []string but %s.", reflect.TypeOf(result).String())
		}
		var publishers []string
		for _, item := range list {
			s, ok := item.(string)
			if !ok {
				logger.Fatal("Publisher list contains no string object")
			}
			publishers = append(publishers, s)
		}

		logger.Debugf("Publisher URI list: %+v", publishers)

		sub = newDefaultSubscriber(name, msgType, callback)
		node.subscribers[name] = sub

		logger.Debugf("Start subscriber goroutine for topic '%s'", sub.topic)
		go sub.start(&node.waitGroup, node.qualifiedName, node.xmlrpcURI, node.masterURI, node.jobChan, logger)
		logger.Debugf("Done")
		sub.pubListChan <- publishers
		logger.Debugf("Update publisher list for topic '%s'", sub.topic)
	} else {
		sub.callbacks = append(sub.callbacks, callback)
	}
	return sub
}

func (node *defaultNode) NewServiceClient(service string, srvType ServiceType) ServiceClient {
	name := node.nameResolver.remap(service)
	client := newDefaultServiceClient(node.logger, node.qualifiedName, node.masterURI, name, srvType)
	return client
}

func (node *defaultNode) NewServiceServer(service string, srvType ServiceType, handler interface{}) ServiceServer {
	name := node.nameResolver.remap(service)
	server, ok := node.servers[name]
	if ok {
		server.Shutdown()
	}
	server = newDefaultServiceServer(node, name, srvType, handler)
	if server == nil {
		return nil
	}
	node.servers[name] = server
	return server
}

func (node *defaultNode) SpinOnce() {
	timeoutChan := time.After(10 * time.Millisecond)
	select {
	case job := <-node.jobChan:
		job()
	case <-timeoutChan:
		break
	}
}

func (node *defaultNode) Spin() {
	logger := node.logger
	for node.OK() {
		timeoutChan := time.After(1000 * time.Millisecond)
		select {
		case job := <-node.jobChan:
			logger.Debug("Execute job")
			job()
		case <-timeoutChan:
			break
		}
	}
}

func (node *defaultNode) Shutdown() {
	node.logger.Debug("Shutting node down")
	node.okMutex.Lock()
	node.ok = false
	node.okMutex.Unlock()
	node.logger.Debug("Shutdown subscribers")
	for _, s := range node.subscribers {
		s.Shutdown()
	}
	node.logger.Debug("Shutdown subscribers...done")
	node.logger.Debug("Shutdown publishers")
	node.publishers.Range(func(key interface{}, value interface{}) bool {
		value.(*defaultPublisher).Shutdown()
		return true
	})
	node.logger.Debug("Shutdown publishers...done")
	node.logger.Debug("Shutdown servers")
	for _, s := range node.servers {
		s.Shutdown()
	}
	node.logger.Debug("Shutdown servers...done")
	node.logger.Debug("Close XMLRPC lisetner")
	node.xmlrpcListener.Close()
	node.logger.Debug("Close XMLRPC done")
	node.logger.Debug("Wait XMLRPC server shutdown")
	node.xmlrpcHandler.WaitForShutdown()
	node.logger.Debug("Wait XMLRPC server shutdown...Done")
	node.logger.Debug("Wait all goroutines")
	node.waitGroup.Wait()
	node.logger.Debug("Wait all goroutines...Done")
	node.logger.Debug("Shutting node down completed")
	return
}

func (node *defaultNode) GetParam(key string) (interface{}, error) {
	name := node.nameResolver.remap(key)
	return callRosAPI(node.masterURI, "getParam", node.qualifiedName, name)
}

func (node *defaultNode) SetParam(key string, value interface{}) error {
	name := node.nameResolver.remap(key)
	_, e := callRosAPI(node.masterURI, "setParam", node.qualifiedName, name, value)
	return e
}

func (node *defaultNode) HasParam(key string) (bool, error) {
	name := node.nameResolver.remap(key)
	result, err := callRosAPI(node.masterURI, "hasParam", node.qualifiedName, name)
	if err != nil {
		return false, err
	}
	hasParam := result.(bool)
	return hasParam, nil
}

func (node *defaultNode) SearchParam(key string) (string, error) {
	result, err := callRosAPI(node.masterURI, "searchParam", node.qualifiedName, key)
	if err != nil {
		return "", err
	}
	foundKey := result.(string)
	return foundKey, nil
}

func (node *defaultNode) DeleteParam(key string) error {
	name := node.nameResolver.remap(key)
	_, err := callRosAPI(node.masterURI, "deleteParam", node.qualifiedName, name)
	return err
}

func (node *defaultNode) Logger() Logger {
	return node.logger
}

func (node *defaultNode) NonRosArgs() []string {
	return node.nonRosArgs
}

func loadParamFromString(s string) (interface{}, error) {
	decoder := json.NewDecoder(strings.NewReader(s))
	var value interface{}
	err := decoder.Decode(&value)
	if err != nil {
		return nil, err
	}
	return value, err
}
