import {
    Aes256Gcm,
    CipherSuite,
    HkdfSha256,
    SenderContextParams,
    RecipientContextParams,
} from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import fetch from 'node-fetch';

class StransportClient {
    private serverUrl: string;
    private suite: CipherSuite;
    private keyPair!: CryptoKeyPair;

    constructor(serverUrl: string) {
        this.serverUrl = serverUrl;
        this.suite = new CipherSuite({
            kem: new DhkemX25519HkdfSha256(),
            kdf: new HkdfSha256(),
            aead: new Aes256Gcm(),
        });
    }

    async initialize(): Promise<void> {
        this.keyPair = await this.suite.kem.generateKeyPair();
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
        const key = await this.suite.kem.importKey("raw", keyData, true);
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
            body: Buffer.from(encrypted),
            headers: {
                'Tinfoil-Client-Public-Key': hexEncode(await this.suite.kem.serializePublicKey(this.keyPair.publicKey)),
                'Tinfoil-Encapsulated-Key': hexEncode(sender.enc)
            }
        });

        if (!response.ok) {
            throw new Error(`Failed to send secure message: ${response.statusText}`);
        }

        const serverEncapKey = response.headers.get('Tinfoil-Encapsulated-Key');
        if (!serverEncapKey) {
            throw new Error('Missing server encapsulated key in response');
        }

        const encryptedResponse = new Uint8Array(await response.arrayBuffer());
        const recipientParams: RecipientContextParams = {
            recipientKey: this.keyPair.privateKey,
            enc: hexDecode(serverEncapKey)
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
                'Accept': 'text/plain',
                'Tinfoil-Client-Public-Key': hexEncode(await this.suite.kem.serializePublicKey(this.keyPair.publicKey)),
                'Tinfoil-Encapsulated-Key': hexEncode(sender.enc)
            }
        });

        if (!response.ok) {
            throw new Error(`Failed to start stream: ${response.statusText}`);
        }

        if (!response.body) {
            throw new Error('Response body is null');
        }

        const serverEncapKey = response.headers.get('Tinfoil-Encapsulated-Key');
        if (!serverEncapKey) {
            throw new Error('Missing server encapsulated key in response');
        }

        const recipientParams: RecipientContextParams = {
            recipientKey: this.keyPair.privateKey,
            enc: hexDecode(serverEncapKey)
        };
        const recipient = await this.suite.createRecipientContext(recipientParams);

        return {
            async *[Symbol.asyncIterator]() {
                const reader = (response.body as unknown as ReadableStream<Uint8Array>).getReader();
                try {
                    while (true) {
                        const { done, value } = await reader.read();
                        if (done) break;
                        
                        if (!value) {
                            throw new Error('Received null chunk from stream');
                        }

                        const decrypted = await recipient.open(new Uint8Array(value));
                        yield new TextDecoder().decode(decrypted);
                    }
                } finally {
                    reader.releaseLock();
                }
            }
        };
    }
}

function hexEncode(buffer: ArrayBuffer): string {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

function hexDecode(hexString: string): ArrayBuffer {
    const matches = hexString.match(/.{1,2}/g);
    if (!matches) {
        throw new Error('Invalid hex string');
    }
    return new Uint8Array(matches.map(byte => parseInt(byte, 16))).buffer;
}

// Example usage
async function main() {
    const client = new StransportClient('http://localhost:8080');
    await client.initialize();
    
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
