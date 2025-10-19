# ffuf-burp-exporter

Convert Burp HTTP requests into ready-to-run `ffuf` commands.  
Drop the Jython script into Burp, right-click a request -> **Send as ffuf command**-> paste into your terminal.

This repo contains a single-file Jython Burp extension that preserves headers, method, body and host/port/proto, and appends `/FUZZ` to the path by default.

## Quick install (for contributors / users)
1. Download the latest **Jython standalone** jar (for Burp Python support).  
2. Open Burp → **Extender** → **Extensions** → **Add**.  
   - Choose `Python` (Jython) as the extension type and load `ffuf_export_all.py`.  
3. Right-click a request in Proxy / HTTP history / Repeater → **Send as ffuf command**.  
4. Paste in terminal, change `-w /path/to/wordlist.txt` to your wordlist and add `-p http://127.0.0.1:8080` if you want ffuf proxied through Burp.

## Example

https://github.com/user-attachments/assets/c78dcac0-1b2e-4a0c-8998-e640f87038b5

