#!/usr/bin/env python3
from pytm import ExternalEntity, DatastoreType
from pytm.pytm import TM, Server, Datastore, Dataflow, Boundary, Actor, Lambda, Data, Classification, Process

tm = TM("DigitalBank")
tm.description = "Threat model for the SimpleDigitalBankingArchitecture"
tm.isOrdered = False
tm.mergeResponses = False
tm.assumptions = []
tm.excluded_findings = []

# Boundaries
azure_vnet = Boundary("Azure VNet Boundary")

internal_corporate = Boundary("Internal Corporate Network")

restricted_network = Boundary("Restricted Network")
restricted_network.inBoundary = internal_corporate

# Actors
user1 = Actor("User1")

user2 = Actor("User2")

# External Entities
browser = ExternalEntity("Browser")

mobile_app = ExternalEntity("Mobile App")

# Processes
azure_waf = Process("Azure WAF")
azure_waf.inBoundary = azure_vnet
azure_waf.protocol = "HTTPS"
azure_waf.data = []
azure_waf.inputs = []
azure_waf.outputs = []
azure_waf.environment = "Production"

azure_webapp = Server("Azure Web App")
azure_webapp.inBoundary = azure_vnet
azure_webapp.usesVPN = True
azure_webapp.protocol = "HTTPS"
azure_webapp.data = []
azure_webapp.inputs = []
azure_webapp.outputs = []

azure_vpn = Process("Azure Express Route VPN")
azure_vpn.inBoundary = azure_vnet
azure_vpn.protocol = "HTTPS"
azure_vpn.data = []
azure_vpn.inputs = []
azure_vpn.outputs = []
azure_vpn.environment = "Production"

azure_webapp_api = Process("Azure Web App API")
azure_webapp_api.inBoundary = azure_vnet
azure_webapp_api.implementsAPI = True
azure_webapp_api.protocol = "HTTPS"
azure_webapp_api.data = []
azure_webapp_api.inputs = []
azure_webapp_api.outputs = []
azure_webapp_api.environment = "Production"

azure_apigateway = Process("Azure API Gateway")
azure_apigateway.inBoundary = azure_vnet
azure_apigateway.implementsAPI = True
azure_apigateway.protocol = "HTTPS"
azure_apigateway.data = []
azure_apigateway.inputs = []
azure_apigateway.outputs = []
azure_apigateway.environment = "Production"

kafka_queue = Server("Apache Kafka Transaction Queue")
kafka_queue.inBoundary = internal_corporate
kafka_queue.usesVPN = True
kafka_queue.data = []
kafka_queue.inputs = []
kafka_queue.outputs = []

bastion_host = Server("Bastion Host")
bastion_host.inBoundary = restricted_network
bastion_host.data = []
bastion_host.inputs = []
bastion_host.outputs = []


# DataStores
webapp_images = Datastore("Web App Images")
webapp_images.inBoundary = azure_vnet
webapp_images.port = 1433
webapp_images.protocol = "HTTP"
webapp_images.data = []
webapp_images.inputs = []
webapp_images.outputs = []
webapp_images.type = DatastoreType.UNKNOWN

azure_sql = Datastore("Azure SQL (Customer Preferences Data)")
azure_sql.inBoundary = azure_vnet
azure_sql.port = 1433
azure_sql.protocol = "TCP"
azure_sql.data = []
azure_sql.inputs = []
azure_sql.outputs = []
azure_sql.hasWriteAccess = True
azure_sql.type = DatastoreType.SQL
azure_sql.isShared = True

bank_mainframe = Datastore("Bank Mainframe (Financial Data)")
bank_mainframe.inBoundary = restricted_network
bank_mainframe.protocol = "TCP"
bank_mainframe.data = []
bank_mainframe.inputs = []
bank_mainframe.outputs = []
bank_mainframe.type = DatastoreType.UNKNOWN
bank_mainframe.storesSensitiveData = True


# DataFlows
user1_browser = Dataflow(user1, browser, "")
browser_user1 = Dataflow(browser, user1, "Retrieve Account Balance")
browser_user1.responseTo = user1_browser

browser_azure_waf = Dataflow(browser, azure_waf, "HTTPS")
browser_azure_waf.protocol = "HTTPS"
browser_azure_waf.isEncrypted = True
azure_waf_browser = Dataflow(azure_waf, browser, "HTTPS")
azure_waf_browser.protocol = "HTTPS"
azure_waf_browser.isEncrypted = True
azure_waf_browser.responseTo = browser_azure_waf

azure_waf_azure_webapp = Dataflow(azure_waf, azure_webapp, "HTTPS")
azure_waf_azure_webapp.protocol = "HTTPS"
azure_waf_azure_webapp.isEncrypted = True
azure_webapp_azure_waf = Dataflow(azure_webapp, azure_waf, "")
azure_webapp_azure_waf.responseTo = azure_waf_azure_webapp

azure_webapp_webapp_images = Dataflow(azure_webapp, webapp_images, "HTTP")
azure_webapp_webapp_images.protocol = "HTTP"
azure_webapp_webapp_images.isEncrypted = False
webapp_images_azure_webapp = Dataflow(webapp_images, azure_webapp, "")
webapp_images_azure_webapp.responseTo = azure_webapp_webapp_images

azure_webapp_azure_sql = Dataflow(azure_webapp, azure_sql, "TCP")
azure_webapp_azure_sql.protocol = "TCP"

azure_webapp_azure_vpn = Dataflow(azure_webapp, azure_vpn, "HTTPS")
azure_webapp_azure_vpn.protocol = "HTTPS"
azure_webapp_azure_vpn.isEncrypted = True
azure_vpn_azure_webapp = Dataflow(azure_vpn, azure_webapp, "")
azure_vpn_azure_webapp.responseTo = azure_webapp_azure_vpn


user2_mobile_app = Dataflow(user2, mobile_app, "")
mobile_app_user2 = Dataflow(mobile_app, user2, "Update Daily Limit")
mobile_app_user2.responseTo = user2_mobile_app

mobile_app_azure_apigateway = Dataflow(mobile_app, azure_apigateway, "HTTPS")
mobile_app_azure_apigateway.protocol = "HTTPS"
mobile_app_azure_apigateway.isEncrypted = True

azure_apigateway_azure_webapp_api = Dataflow(azure_apigateway, azure_webapp_api, "HTTPS")
azure_apigateway_azure_webapp_api.protocol = "HTTPS"
azure_apigateway_azure_webapp_api.isEncrypted = True
azure_webapp_api_azure_apigateway = Dataflow(azure_webapp_api, azure_apigateway, "")
azure_webapp_api_azure_apigateway.responseTo = azure_apigateway_azure_webapp_api

azure_webapp_api_azure_sql = Dataflow(azure_webapp_api, azure_sql, "TCP")
azure_webapp_api_azure_sql.protocol = "TCP"

azure_webapp_api_azure_vpn = Dataflow(azure_webapp_api, azure_vpn, "HTTPS")
azure_webapp_api_azure_vpn.protocol = "HTTPS"
azure_webapp_api_azure_vpn.isEncrypted = True
azure_vpn_azure_webapp_api = Dataflow(azure_vpn, azure_webapp_api, "")
azure_vpn_azure_webapp_api.responseTo = azure_webapp_api_azure_vpn

azure_vpn_kafka_queue = Dataflow(azure_vpn, kafka_queue, "")
kafka_queue_azure_vpn = Dataflow(kafka_queue, azure_vpn, "")
kafka_queue_azure_vpn.responseTo = azure_vpn_kafka_queue

kafka_queue_bastion_host = Dataflow(kafka_queue, bastion_host, "TCP")
kafka_queue_bastion_host.protocol = "TCP"
bastion_host_kafka_queue = Dataflow(bastion_host, kafka_queue, "")
bastion_host_kafka_queue.responseTo = kafka_queue_bastion_host

bastion_host_bank_mainframe = Dataflow(bastion_host, bank_mainframe, "TCP")
bastion_host_bank_mainframe.protocol = "TCP"
bank_mainframe_bastion_host = Dataflow(bank_mainframe, bastion_host, "")


if __name__ == '__main__':
    tm.process()
