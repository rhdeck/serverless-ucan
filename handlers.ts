import "./core";
import {
  httpSuccess,
  makeAPIGatewayLambda,
  sendHttpResult,
} from "@raydeck/serverless-lambda-builder";
import { APIGatewayProxyHandler } from "aws-lambda";
import fetch from "node-fetch";
import { KeyPair } from "ucan-storage-commonjs/keypair";
import { build, validate } from "ucan-storage-commonjs/ucan-storage";
//#region UCAN Management
const rootTokens: Record<string, string> = {};
const nsServiceKey = "did:key:z6MknjRbVGkfWK1x5gyJZb6D4LjMj1EsitFzcSccS3sAaviQ";
const issuerKeyPair = new KeyPair(
  Buffer.from(process.env.DID_PRIVATE_KEY ?? "", "base64"),
  Buffer.from(process.env.DID_PUBLIC_KEY ?? "", "base64")
);
const badKeys: Record<string, boolean> = {};
export const getUCANToken = makeAPIGatewayLambda({
  timeout: 30,
  method: "get",
  cors: true,
  path: "/ucan-token",
  func: <APIGatewayProxyHandler>(async (event) => {
    const { body } = event;
    if (!body) return sendHttpResult(400, "No body");
    const { apiKey } = JSON.parse(body);
    if (badKeys[apiKey]) return sendHttpResult(401, "Bad API Key");
    if (!rootTokens[apiKey].length) {
      const url = "https://api.nft.storage/ucan/token";
      const response = await fetch(url, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${apiKey}`,
        },
      });
      if (response.status !== 200) {
        badKeys[apiKey] = true;
        return sendHttpResult(401, "Bad API Key");
      }
      const retJSON = await response.json();
      rootTokens[apiKey] = retJSON.value;
    }
    const { payload } = await validate(rootTokens[apiKey]);
    const { att } = payload;
    const capabilities = att.map((capability) => ({
      ...capability,
      with: [capability.with, nsServiceKey].join("/"),
    }));
    const proofs = [rootTokens[apiKey]];
    const token = await build({
      issuer: issuerKeyPair,
      audience: nsServiceKey,
      capabilities: capabilities as any,
      proofs,
      lifetimeInSeconds: 100,
    });
    return httpSuccess({ token, did: process.env.DID });
  }),
});
//#endregion
