import {
    Aes256Gcm,
    CipherSuite,
    HkdfSha256,
    SenderContextParams,
    RecipientContextParams,
} from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import fetch from 'node-fetch';
import * as ed25519 from '@stablelib/ed25519';

class StransportClient {
    private serverUrl: string;
    private suite: CipherSuite;

    constructor(serverUrl: string) {
        this.serverUrl = serverUrl;
        this.suite = new CipherSuite({
            kem: new DhkemX25519HkdfSha256(),
            kdf: new HkdfSha256(),
            aead: new Aes256Gcm(),
        });
    }

    async getServerPublicKey(): Promise<CryptoKey> {
        const response = await fetch(`${this.serverUrl}/.well-known/tinfoil-public-key`);
        if (!response.ok) {
            throw new Error(`Failed to get server public key: ${response.statusText}`);
        }
        const hexKey = await response.text();
        const matches = hexKey.match(/.{1,2}/g);
        if (!matches) {
            throw new Error('Invalid public key format');
        }
        const keyData = new Uint8Array(matches.map(byte => parseInt(byte, 16)));
        if (keyData.byteLength !== 32) {
            throw new Error('Invalid public key length');
        }
        const key = await this.suite.kem.importKey("raw", ed25519.convertPublicKeyToX25519(new Uint8Array(keyData)), true);
        return key;
    }

    async sendSecureMessage(message: string): Promise<string> {
        const serverPublicKey = await this.getServerPublicKey();
        const senderParams: SenderContextParams = {
            recipientPublicKey: serverPublicKey
        };
        const sender = await this.suite.createSenderContext(senderParams);

        const encrypted = await sender.seal(new TextEncoder().encode(message));
        const response = await fetch(`${this.serverUrl}/secure`, {
            method: 'POST',
            body: Buffer.from(encrypted)
        });

        if (!response.ok) {
            throw new Error(`Failed to send secure message: ${response.statusText}`);
        }

        const encryptedResponse = new Uint8Array(await response.arrayBuffer());
        const recipientParams: RecipientContextParams = {
            recipientKey: serverPublicKey,
            enc: sender.enc
        };
        const recipient = await this.suite.createRecipientContext(recipientParams);

        const decrypted = await recipient.open(encryptedResponse);
        return new TextDecoder().decode(decrypted);
    }

    async streamMessages(): Promise<AsyncIterable<string>> {
        const serverPublicKey = await this.getServerPublicKey();
        const senderParams: SenderContextParams = {
            recipientPublicKey: serverPublicKey
        };
        const sender = await this.suite.createSenderContext(senderParams);

        const response = await fetch(`${this.serverUrl}/stream`, {
            method: 'GET',
            headers: {
                'Accept': 'text/plain'
            }
        });

        if (!response.ok) {
            throw new Error(`Failed to start stream: ${response.statusText}`);
        }

        if (!response.body) {
            throw new Error('Response body is null');
        }

        const recipientParams: RecipientContextParams = {
            recipientKey: serverPublicKey,
            enc: sender.enc
        };
        const recipient = await this.suite.createRecipientContext(recipientParams);

        const reader = (response.body as unknown as ReadableStream<Uint8Array>).getReader();

        return {
            async *[Symbol.asyncIterator]() {
                try {
                    while (true) {
                        const { done, value } = await reader.read();
                        if (done) break;
                        
                        if (!value) {
                            throw new Error('Received null chunk from stream');
                        }

                        const decrypted = await recipient.open(new Uint8Array(value.buffer));
                        yield new TextDecoder().decode(decrypted);
                    }
                } finally {
                    reader.releaseLock();
                }
            }
        };
    }
}

// Example usage
async function main() {
    const client = new StransportClient('http://localhost:8080');
    
    try {
        // Test secure message
        const response = await client.sendSecureMessage('World');
        console.log('Secure message response:', response);

        // Test streaming
        console.log('Streaming messages:');
        for await (const message of await client.streamMessages()) {
            console.log(message);
        }
    } catch (error) {
        console.error('Error:', error);
    }
}

main();
