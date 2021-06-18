/**
 * Copyright 2013,2014 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

module.exports = function (RED) {
  'use strict';
  const jwt_decode = require("jwt-decode");
  const aedes = require('aedes');
  const net = require('net');
  const tls = require('tls');
  const http = require('http');
  const https = require('https');
  const ws = require('websocket-stream');

  const fs = require("fs");
  const querystring = require('querystring');

  let serverUpgradeAdded = false;
  const listenerNodes = {};

  const accessTokenCache = {};

  function handleServerUpgrade (request, socket, head) {
    const pathname = new URL(request.url, 'http://example.org').pathname;
    if (Object.prototype.hasOwnProperty.call(listenerNodes, pathname)) {
      listenerNodes[pathname].server.handleUpgrade(request, socket, head, function done (conn) {
        listenerNodes[pathname].server.emit('connection', conn, request);
      });
    }
  }
  function obtainPermissionByPassword(config, accountname, accesskey) { 
    return new Promise((resolve, reject) => {
      //cachec operation start
      let key = JSON.stringify({
        preferred_username: accountname
      });
  
      let cacheToken = accessTokenCache[key];
      if(cacheToken && cacheToken.acceess_token && cacheToken.acceess_token.exp > (new Date().getTime())/1000){
        resolve(cacheToken.acceess_token);
        return;
      }else if(cacheToken){
        if(!accesskey) accesskey = cacheToken.pwd;
        delete accessTokenCache[key];
      }
      //cache operation end		
      const body = querystring.stringify({
        grant_type: 'password',
        username: `${accountname}`,
        password: `${accesskey}`,
        audience: config.idpClient
      });
      // console.log(body);
      let base64Data = new Buffer.from(config.idpClient+":"+config.idpClientCredential).toString('base64');
      const options = {
        "hostname": config.idpHost,
        "port": config.idpPort,
        "path": config.idpURI,
        "method": 'POST',
        "headers": {
          "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
          "Content-Length": Buffer.byteLength(body),
          "Authorization": `Basic ${base64Data}`
        }
      }
      // console.log(options);
      let httpClient = (config.idpUsetls)? https: http;
      const req = httpClient.request(options, res => {
        // console.log(`statusCode: ${res.statusCode}`)
        if(res.statusCode != 200){
          reject("No permission");
        }else{
          const chunks = [];
          res.on('data', data => chunks.push(data))
          res.on('end', () => {
            let body = Buffer.concat(chunks);
            let bearer_acceess_token = body.toString();
            let accessToken = jwt_decode(bearer_acceess_token);
            // console.log(JSON.stringify(accessToken));

            //cache operation start
            let key = JSON.stringify({
              preferred_username: accessToken.preferred_username
            });
            let cacheToken = {
              pwd: `${accesskey}`,
              acceess_token: accessToken
            };
            accessTokenCache[key] = cacheToken;
            //cache operation end			
            // console.log(JSON.stringify(cacheToken));

            resolve(accessToken);
          })
        }
      })
      req.on('error', reject);
      req.write(body);
      req.end();
    })
  }

  function AedesBrokerNode (config) {
    RED.nodes.createNode(this, config);
    //-------------start of configuration overwrite------------
    this.credentials = null;
    this.username = null;
    this.password = null;
    this.cert = null;
    this.key = null;    
    config.mqtt_port = process.env.AEDES_MQTT_PORT;
    config.mqtt_ws_port = process.env.AEDES_MQTT_WS_PORT;
    config.mqtt_ws_path = process.env.AEDES_MQTT_WS_PATH;
    config.mqtt_ws_bind = process.env.AEDES_MQTT_WS_BIND;

    config.idpHost=process.env.IDP_HOST;
    config.idpPort= parseInt(process.env.IDP_PORT, 10);
    config.idpClient=process.env.IDP_CLIENT; //TOAI
    config.idpRealm=process.env.IDP_REALM //toai
    config.idpClientCredential = process.env.IDP_CLIENTCREDENTIAL;
    config.idpUsetls =  (process.env.IDP_USETLS === 'true');
    config.idpURI = `/auth/realms/${config.idpRealm}/protocol/openid-connect/token`;    
    config.authzConfigJson = JSON.parse(fs.readFileSync('/data/authz-config.json'));
    //-------------end of configuration overwrite------------

    this.mqtt_port = parseInt(config.mqtt_port, 10);
    this.mqtt_ws_port = parseInt(config.mqtt_ws_port, 10);
    this.mqtt_ws_path = '' + config.mqtt_ws_path;
    this.mqtt_ws_bind = config.mqtt_ws_bind;

    if (this.mqtt_ws_bind === 'path') {
      this.mqtt_ws_port = 0;
    } else {
      this.mqtt_ws_path = '';
    }

    const node = this;

    const aedesSettings = {};

    const broker = new aedes.Server(aedesSettings);
    let server = net.createServer(broker.handle);

    let wss = null;
    let httpServer = null;

    if (this.mqtt_ws_port) {
      // Awkward check since http or ws do not fire an error event in case the port is in use
      const testServer = net.createServer();
      testServer.once('error', function (err) {
        if (err.code === 'EADDRINUSE') {
          node.error('Error: Port ' + config.mqtt_ws_port + ' is already in use');
        } else {
          node.error('Error creating net server on port ' + config.mqtt_ws_port + ', ' + err.toString());
        }
      });
      testServer.once('listening', function () {
        testServer.close();
      });

      testServer.once('close', function () {
        httpServer = http.createServer();
        wss = ws.createServer({
          server: httpServer
        }, broker.handle);
        httpServer.listen(config.mqtt_ws_port, function () {
          node.log('Binding aedes mqtt server on ws port: ' + config.mqtt_ws_port);
        });
      });
      testServer.listen(config.mqtt_ws_port, function () {
        node.log('Checking ws port: ' + config.mqtt_ws_port);
      });
    }

    if (this.mqtt_ws_path !== '') {
      if (!serverUpgradeAdded) {
        RED.server.on('upgrade', handleServerUpgrade);
        serverUpgradeAdded = true;
      }

      let path = RED.settings.httpNodeRoot || '/';
      path = path + (path.slice(-1) === '/' ? '' : '/') + (node.mqtt_ws_path.charAt(0) === '/' ? node.mqtt_ws_path.substring(1) : node.mqtt_ws_path);
      node.fullPath = path;

      if (Object.prototype.hasOwnProperty.call(listenerNodes, path)) {
        node.error(RED._('websocket.errors.duplicate-path', { path: node.mqtt_ws_path }));
        return;
      }
      listenerNodes[node.fullPath] = node;
      const serverOptions_ = {
        noServer: true
      };
      if (RED.settings.webSocketNodeVerifyClient) {
        serverOptions_.verifyClient = RED.settings.webSocketNodeVerifyClient;
      }

      node.server = ws.createServer({
        noServer: true
      }, broker.handle);

      node.log('Binding aedes mqtt server on ws path: ' + node.fullPath);
    }

    server.once('error', function (err) {
      if (err.code === 'EADDRINUSE') {
        node.error('Error: Port ' + config.mqtt_port + ' is already in use');
        node.status({ fill: 'red', shape: 'ring', text: 'node-red:common.status.disconnected' });
      } else {
        node.error('Error: Port ' + config.mqtt_port + ' ' + err.toString());
        node.status({ fill: 'red', shape: 'ring', text: 'node-red:common.status.disconnected' });
      }
    });

    if (this.mqtt_port) {
      server.listen(this.mqtt_port, function () {
        node.log('Binding aedes mqtt server on port: ' + config.mqtt_port);
        node.status({ fill: 'green', shape: 'dot', text: 'node-red:common.status.connected' });
      });
    }

    // if (this.credentials && this.username && this.password) {
      const authenticate = function (client, username, password, callback) {
        if(client && client.req && client.req.upgrade){
          console.info("websocket without checking");
          callback(null, true);
          return;
        }      
        if (username && password){ 
          obtainPermissionByPassword(config, username, password) 
          .then(accessToken => {
            client.user = username;		
            callback(null, true);
            return;
          })
          .catch(err => {
            callback(null, false);
            return;
          })
        }else{
          callback(null, false);
          return;
        }
      };

      broker.authenticate = authenticate;
    // }
    
    const authorizeCallback = function(callback,subscription){
      if(subscription){
        callback(null, subscription);
      }else{
        callback(null);
      }
    }

    const authorizeHandler = function(client, topic, callback, subscription){
      var tmp = topic.split("/");
      var site;
      var accountname = client.user;
      if(tmp && tmp.length>3){
        site = tmp[3];
      }else{
        site = null;
      }      
      if(client && !client.user && client.req && client.req.headers && client.req.headers.access_token ){
        let accessToken = jwt_decode(client.req.headers.access_token);
        if(accessToken.groups.includes("/site") || ( site && accessToken.groups.includes("/site/"+site) ) ){
          if(!subscription && accessToken.resource_access[config.idpClient].roles.includes("writter")){
            return authorizeCallback(callback, subscription);
          }else if(subscription && accessToken.resource_access[config.idpClient].roles.includes("reader")){
            return authorizeCallback(callback, subscription);
          }else{
            return callback(new Error('No Permission'));
          }
        }else{
          return callback(new Error('No Permission'));
        }
      }else if(client && client.user){
          obtainPermissionByPassword(config,accountname, null)
          .then(accessToken => {
            if(accessToken.groups.includes("/site") || ( site && accessToken.groups.includes("/site/"+site) ) ){
              if(!subscription && accessToken.resource_access[config.idpClient].roles.includes("writter")){
                return authorizeCallback(callback, subscription);
              }else if(subscription && accessToken.resource_access[config.idpClient].roles.includes("reader")){
                return authorizeCallback(callback, subscription);
              }else{
                return callback(new Error('No Permission'));
              }
            }else{
              return callback(new Error('No Permission'));
            }
          })
          .catch(err => {
            return callback(new Error('No Permission'));
          })
      } else{
        return callback(new Error('No Permission'));
      }
    }


    const authorizePublishHandler = function (client, packet, callback) {
      return authorizeHandler(client, packet.topic, callback, null);
    }

    const authorizeSubscribeHandler =function (client, subscription, callback) {
      return authorizeHandler(client, subscription.topic, callback, subscription);
    } 
    broker.authorizePublish =  authorizePublishHandler;
    broker.authorizeSubscribe =  authorizeSubscribeHandler;


    broker.on('client', function (client) {
      const msg = {
        topic: 'client',
        payload: {
          client: client
        }
      };
      node.send(msg);
    });

    broker.on('clientReady', function (client) {
      const msg = {
        topic: 'clientReady',
        payload: {
          client: client
        }
      };
      node.status({ fill: 'green', shape: 'dot', text: RED._('aedes-mqtt-broker.status.connected', { count: broker.connectedClients }) });
      node.send(msg);
    });

    broker.on('clientDisconnect', function (client) {
      const msg = {
        topic: 'clientDisconnect',
        payload: {
          client: client
        }
      };
      node.send(msg);
      node.status({ fill: 'green', shape: 'dot', text: RED._('aedes-mqtt-broker.status.connected', { count: broker.connectedClients }) });
    });

    broker.on('clientError', function (client, err) {
      const msg = {
        topic: 'clientError',
        payload: {
          client: client,
          err: err
        }
      };
      node.send(msg);
      node.status({ fill: 'green', shape: 'dot', text: RED._('aedes-mqtt-broker.status.connected', { count: broker.connectedClients }) });
    });

    broker.on('connectionError', function (client, err) {
      const msg = {
        topic: 'connectionError',
        payload: {
          client: client,
          err: err
        }
      };
      node.send(msg);
      node.status({ fill: 'green', shape: 'dot', text: RED._('aedes-mqtt-broker.status.connected', { count: broker.connectedClients }) });
    });

    broker.on('keepaliveTimeout', function (client) {
      const msg = {
        topic: 'keepaliveTimeout',
        payload: {
          client: client
        }
      };
      node.send(msg);
      node.status({ fill: 'green', shape: 'dot', text: RED._('aedes-mqtt-broker.status.connected', { count: broker.connectedClients }) });
    });

    broker.on('subscribe', function (subscription, client) {
      const msg = {
        topic: 'subscribe',
        payload: {
          topic: subscription.topic,
          qos: subscription.qos,
          client: client
        }
      };
      node.send(msg);
    });

    broker.on('unsubscribe', function (subscription, client) {
      const msg = {
        topic: 'unsubscribe',
        payload: {
          topic: subscription.topic,
          qos: subscription.qos,
          client: client
        }
      };
      node.send(msg);
    });

    /*
    broker.on('publish', function (packet, client) {
      var msg = {
        topic: 'publish',
        payload: {
          packet: packet,
          client: client
        }
      };
      node.send(msg);
    });
     */

    broker.on('closed', function () {
      node.debug('Closed event');
    });
    this.on('close', function (done) {
      broker.close(function () {
        node.log('Unbinding aedes mqtt server from port: ' + config.mqtt_port);
        server.close(function () {
          node.debug('after server.close(): ');
          if (node.mqtt_ws_path !== '') {
            node.log('Unbinding aedes mqtt server from ws path: ' + node.fullPath);
            delete listenerNodes[node.fullPath];
            node.server.close();
          }          
          if (wss) {
            node.log('Unbinding aedes mqtt server from ws port: ' + config.mqtt_ws_port);
            wss.close(function () {
              node.debug('after wss.close(): ');
              httpServer.close(function () {
                node.debug('after httpServer.close(): ');
                done();
              });
            });
          } else {
            done();
          }
        });
      });
    });
  }

  RED.nodes.registerType('aedes broker', AedesBrokerNode, {
  });
};
