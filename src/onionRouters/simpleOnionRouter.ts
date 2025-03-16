import bodyParser from "body-parser";
import express from "express";
import axios from "axios";
import crypto from "crypto";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import { generateRsaKeyPair, rsaDecrypt, symDecrypt } from "../crypto";

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  // /status route.
  onionRouter.get("/status", (req, res) => {
    res.send("live");
  });

  // State variables for testing.
  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;

  // GET routes for test verification.
  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({ result: lastReceivedEncryptedMessage });
  });
  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({ result: lastReceivedDecryptedMessage });
  });
  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.json({ result: lastMessageDestination });
  });

  // Generate RSA key pair.
  const keyPair = await generateRsaKeyPair();
  const publicKeyBuffer = await crypto.webcrypto.subtle.exportKey("spki", keyPair.publicKey);
  const exportedPublicKey = Buffer.from(publicKeyBuffer).toString("base64");

  const privateKeyBuffer = await crypto.webcrypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  const exportedPrivateKey = Buffer.from(privateKeyBuffer).toString("base64");

  // Expose the private key (base64) for testing.
  onionRouter.get("/getPrivateKey", (req, res) => {
    res.json({ result: exportedPrivateKey });
  });

  // POST /message: Peel one encryption layer and forward the inner message.
  onionRouter.post("/message", async (req, res) => {
    try {
      const { message } = req.body;
      lastReceivedEncryptedMessage = message;

      // Expect message format: "encryptedKey||encryptedPayload".
      const parts = message.split("||");
      if (parts.length !== 2) {
        res.status(400).send("Invalid message format");
        return;
      }
      const [encryptedKeyBase64, encryptedPayload] = parts;

      const symmetricKeyBuffer = await rsaDecrypt(encryptedKeyBase64, keyPair.privateKey);
      const symmetricKeyStr = Buffer.from(symmetricKeyBuffer).toString("base64");
      const decryptedPayload = await symDecrypt(symmetricKeyStr, encryptedPayload);

      lastReceivedDecryptedMessage = decryptedPayload;

      // The first 10 characters represent the next destination port.
      const destStr = decryptedPayload.substring(0, 10);
      const nextDestination = parseInt(destStr, 10);
      lastMessageDestination = nextDestination;

      // The inner message is the remainder.
      const innerMessage = decryptedPayload.substring(10);
      if (innerMessage) {
        await axios.post(`http://localhost:${nextDestination}/message`, { message: innerMessage });
      }
      res.json({ result: "message processed" });
    } catch (error) {
      console.error("Error processing message:", error);
      res.status(500).send("Error processing message");
    }
  });

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
      `Onion router ${nodeId} is listening on port ${BASE_ONION_ROUTER_PORT + nodeId}`
    );
  });

  // Register this node with the registry.
  try {
    await axios.post(`http://localhost:${REGISTRY_PORT}/registerNode`, {
      nodeId,
      pubKey: exportedPublicKey,
    });
    console.log(`Node ${nodeId} registered with registry.`);
  } catch (error) {
    console.error("Error registering node:", error);
  }

  return server;
}
