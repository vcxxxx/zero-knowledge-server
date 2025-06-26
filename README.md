# zero-knowledge-server
A zero-knowledge file storage and sharing server built with Flask. Files are encrypted with symmetric keys, which are then securely shared using clients’ public RSA keys. Includes JWT, 2FA, TLS, and challenge-response authentication for strong security.


Run the following command in the main directory -

```bash
pip3 install -r requirements.txt
```

To start the server, navigate to the server directory and run the following command - 
```bash
python3 server.py
```
To start the client, navigate to the client directory and run the following command -

```bash
python3 client.py
```
