'''
Verify basic PROXY protocol functionality.
'''
# @file
#
# Copyright 2023, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

import re

Test.Summary = '''
Verify basic PROXY protocol functionality.
'''


class PPTest:
    # static id for client, server and proxy processes
    test_id = 1

    def __init__(self, testBaseName, ppVersion, isHTTPS, testRunDesc=""):
        self.testRun = Test.AddTestRun(testRunDesc)
        self.testBaseName = testBaseName
        self.ppVersion = ppVersion
        self.replayFile = f'replay_files/{testBaseName}_pp_v{ppVersion}.replay.yaml'
        self.isHTTPS = isHTTPS

    def setupClient(self, isHTTPS):
        self.client = self.testRun.AddClientProcess(
            f"client-{PPTest.test_id}", self.replayFile, configure_http=not isHTTPS, configure_https=isHTTPS)

    def setupServer(self, isHTTPS):
        self.server = self.testRun.AddServerProcess(
            f"server-{PPTest.test_id}", self.replayFile, configure_http=not isHTTPS, configure_https=isHTTPS)

    def setupProxy(self, isHTTPS):
        # TODO: use the isHTTPS argument to configure the proxy to use SSL(different port)
        self.proxyListenPort = self.client.Variables.https_port if isHTTPS else self.client.Variables.http_port
        self.serverListenPort = self.server.Variables.https_port if isHTTPS else self.server.Variables.http_port
        self.proxy = self.testRun.AddProxyProcess(
            f"proxy-{PPTest.test_id}", listen_port=self.proxyListenPort, server_port=self.serverListenPort, use_ssl=isHTTPS)

    def setupTransactionLogsVerification(self):
        # Verify that the http trasactions are successful(not hindered by the
        # PROXY protocol processing).
        self.proxy.Streams.stdout = f"gold/{self.testBaseName}_proxy.gold"
        self.client.Streams.stdout = f"gold/{self.testBaseName}_client.gold"
        self.server.Streams.stdout = f"gold/{self.testBaseName}_server.gold"

    def setupPPLogsVerification(self):
        # Verify the PROXY protocol related logs
        self.client.Streams.stdout += Testers.ContainsExpression(
            f"Sending PROXY header from 127\.0\.0\.1:[0-9]+ to 127\.0\.0\.1:{self.proxyListenPort}",
            "Verify that the PROXY header is sent from the client to the proxy.")

        self.proxy.Streams.stdout += Testers.ContainsExpression(
            f"Received .* bytes of Proxy Protocol V{self.ppVersion}",
            "Verify that the PROXY header is received by the proxy.")
        self.proxy.Streams.stdout += Testers.ContainsExpression(
            f"PROXY TCP4 127\.0\.0\.1 127\.0\.0\.1 [0-9]+ {self.proxyListenPort}",
            "Verify the PROXY header content.")

        self.server.Streams.stdout += Testers.ContainsExpression(
            f"Received PROXY header v{self.ppVersion}:.*\nPROXY TCP4 127\.0\.0\.1 127\.0\.0\.1 [0-9]+ {self.serverListenPort}",
            "Verify that the PROXY header is received by the server.", reflags=re.MULTILINE)

    def run(self):
        self.setupClient(self.isHTTPS)
        self.setupServer(self.isHTTPS)
        self.setupProxy(self.isHTTPS)
        self.setupTransactionLogsVerification()
        self.setupPPLogsVerification()
        PPTest.test_id += 1


# Test 1: Verify the PROXY header v1 is sent and received in a HTTP transaction.
PPTest("http_single_transaction", ppVersion=1, isHTTPS=False,
       testRunDesc="Verify PROXY protocol v1 is sent and received in a HTTP transaction").run()

# Test 2: Verify the PROXY header v2 is sent and received in a HTTP transaction.
PPTest("http_single_transaction", ppVersion=2, isHTTPS=False,
       testRunDesc="Verify PROXY protocol v2 is sent and received in a HTTP transaction").run()
