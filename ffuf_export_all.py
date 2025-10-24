from burp import IBurpExtender, IContextMenuFactory
from java.util import ArrayList
from javax.swing import JMenuItem, JOptionPane
from java.awt.datatransfer import StringSelection
from java.awt import Toolkit
import re

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("ffuf-everything-export")
        callbacks.registerContextMenuFactory(self)
        return

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        item = JMenuItem("Send as ffuf command", actionPerformed=lambda e, inv=invocation: self.onSend(inv))
        menu_list.add(item)
        return menu_list

    def onSend(self, invocation):
        try:
            msgs = invocation.getSelectedMessages()
            if not msgs:
                JOptionPane.showMessageDialog(None, "No request selected.")
                return
            rr = msgs[0]  # handle first selected
            request = rr.getRequest()
            analyzed = self._helpers.analyzeRequest(rr)
            headers = analyzed.getHeaders()
            body_offset = analyzed.getBodyOffset()
            request_bytes = request
            # get whole request as string then slice for body (works with Burp Java byte[] via helpers)
            try:
                request_str = self._helpers.bytesToString(request_bytes)
            except:
                # fallback to str() if helpers not available for some reason
                request_str = str(request_bytes)
            if body_offset < len(request_bytes):
                body = request_str[body_offset:]
            else:
                body = ""

            service = rr.getHttpService()
            proto = service.getProtocol() if hasattr(service, "getProtocol") else ("https" if service.getPort()==443 else "http")
            host = service.getHost()
            port = service.getPort()
            # include port explicitly to match Host header behavior (user asked for full transform)
            base = "%s://%s:%s" % (proto, host, port)

            # parse request-line to get path portion
            req_line = headers[0]
            # ensure we have a Python str (handle bytes/header objects)
            try:
                if isinstance(req_line, bytes):
                    req_line = self._helpers.bytesToString(req_line)
                else:
                    req_line = str(req_line)
            except:
                req_line = str(req_line)
            req_line = req_line.strip()

            # split robustly: method, path, [version]
            parts = req_line.split(None, 2)
            if len(parts) < 2:
                JOptionPane.showMessageDialog(None, "Couldn't parse request line: %s" % req_line)
                return
            method = parts[0].upper()
            path = parts[1]

            # handle absolute-form request-line (proxy requests) -> extract path only
            if path.lower().startswith("http://") or path.lower().startswith("https://"):
                m2 = re.match(r'https?://[^/]+(:\d+)?(/.*)', path, re.I)
                if m2:
                    path = m2.group(2)
                else:
                    path = "/"

            # ignore methods that don't map to ffuf target URLs
            if method == "CONNECT" or path == "*":
                JOptionPane.showMessageDialog(None, "Can't convert CONNECT/* pseudo-requests to ffuf.")
                return

            # always append FUZZ at the end of path (user asked not to worry about fuzz placement)
            if path.endswith("/"):
                target_url = base + path + "FUZZ"
            else:
                # avoid creating double slashes if path already starts with '/'
                if path.startswith("/"):
                    target_url = base + path + "/FUZZ"
                else:
                    target_url = base + "/" + path + "/FUZZ"

            # build ffuf parts
            parts = ["ffuf"]

            # URL
            parts += ["-u", self.shell_quote(target_url)]

            # add headers (skip Host and Content-Length)
            for h in headers[1:]:
                # header lines can include weird spacing; rebuild cleanly
                if ":" not in h:
                    continue
                name = h.split(":",1)[0].strip().lower()
                if name in ("host", "content-length"):
                    continue
                parts += ["-H", self.shell_quote(h)]

            # method if not GET
            if method != "GET":
                parts += ["-X", method]

            # include body if present (keep original raw body)
            if body:
                # prefer to preserve body exactly, but quote it
                parts += ["-d", self.shell_quote(body)]

            # default placeholders (user can edit in terminal)
            parts += ["-w", "/path/to/wordlist.txt"]
            parts += ["-mc", "200,301,302"]
            # common proxy hint (commented for user to enable manually)
            # parts += ["-p", "http://127.0.0.1:8080"]

            final = " ".join(parts)
            self.copy_to_clipboard(final)
            # show trimmed preview
            preview = final if len(final) < 600 else final[:600] + " ... (truncated)"
            JOptionPane.showMessageDialog(None, "ffuf command copied to clipboard:\n\n" + preview)
        except Exception as e:
            JOptionPane.showMessageDialog(None, "Error: %s" % (str(e)))

    def shell_quote(self, s):
        if s is None:
            return "''"
        s = str(s)
        if "'" not in s:
            return "'" + s + "'"
        # escape single quotes using '"'"' idiom
        return "'" + s.replace("'", "'\"'\"'") + "'"

    def copy_to_clipboard(self, text):
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        sel = StringSelection(text)
        clipboard.setContents(sel, None)
