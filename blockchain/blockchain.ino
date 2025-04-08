#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <Web3.h>
#include "Contract.h"

const char *ssid = "<your-ssid>";
const char *password = "<your-password>";

const std::string myAddress = "<your-address>";
std::string contractAddress = "<contract-address>";

Web3 web3("polygon-mainnet.infura.io", "/v3/<your-infura-project-id>");

void eth_send_example();

void setup()
{
  Serial.begin(115200);

  Serial.print("Connecting to WiFi");
  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED)
  {
    delay(1000);
    Serial.print(".");
  }
  Serial.println("\nConnected to WiFi");
  Serial.println(WiFi.localIP());

  eth_send_example();
}

void loop()
{
  // Add your loop code here if needed
}

void eth_send_example()
{
  Contract contract(&web3, contractAddress.c_str());

  uint32_t nonce = web3.EthGetTransactionCount(&myAddress);
  Serial.println(nonce);

  std::string p = contract.SetupContractData("receiveData(string memory)", "Hello world");
  Serial.println(p.c_str());

  contract.SetPrivateKey("<your-private-key>");
  std::string zeroValue = "0x00";

  Serial.println(
      contract.SendTransaction(nonce, 40000000000, 200000, &contractAddress, &zeroValue, &p).c_str());
}
