import sys
import requests
import base64
import json
import yaml
from ruamel.yaml import YAML
from urllib.parse import urlparse, parse_qs, unquote


# ---------- UTILITIES ----------
def download_subscription(sub_url):
    resp = requests.get(sub_url)
    resp.raise_for_status()
    text = resp.text.strip()
    # meta: some sub files are base64 encoded!
    try:
        if all(ord(c) < 128 for c in text) and not text.startswith('vmess://'):
            # Try decode base64 whole (often for SSR/SS)
            dec = base64.b64decode(text).decode('utf-8', errors='ignore')
            if dec.count('\n') > text.count('\n'):
                text = dec
    except Exception:
        pass
    return [line.strip() for line in text.splitlines() if line.strip()]


# --- PROTOCOL PARSERS ---
def parse_vmess(uri):
    # vmess://<base64json>
    payload = uri[8:]
    try:
        raw = base64.b64decode(payload + '=' * ((4 - len(payload) % 4) % 4)).decode('utf-8')
        data = json.loads(raw)
        proxy = {
            'type': 'vmess',
            'server': data.get('add'),
            'port': int(data.get('port', 0)),
            'uuid': data.get('id'),
            'alterId': data.get('aid', '0'),
            'cipher': data.get('cipher', ''),  # optional
            'network': data.get('net', ''),
            'tls': (data.get('tls', 'none') == 'tls'),
            'name': data.get('ps') or f"vmess_{data.get('add')}",
        }
        return proxy
    except Exception:
        return None


def parse_vless(uri):
    # vless://[uuid]@[host]:[port]?params#remark
    url = urlparse(uri)
    user = url.username
    server = url.hostname
    port = url.port
    params = parse_qs(url.query)
    tag = unquote(url.fragment) if url.fragment else f"vless_{server}"
    return {
        'type': 'vless',
        'server': server,
        'port': int(port),
        'uuid': user,
        'encryption': params.get('encryption', ['none'])[0],
        'flow': params.get('flow', [''])[0],
        'network': params.get('type', ['tcp'])[0],
        'tls': 'tls' in params and params['tls'][0] == 'tls',
        'name': tag,
    }


def parse_trojan(uri):
    # trojan://password@host:port?params#remark
    url = urlparse(uri)
    server = url.hostname
    port = url.port
    password = url.username
    tag = unquote(url.fragment) if url.fragment else f"trojan_{server}"
    return {
        'type': 'trojan',
        'server': server,
        'port': int(port),
        'password': password,
        'name': tag
    }


def parse_ss(uri):
    # ss://[method:pass@host:port] or ss://base64#remark
    try:
        rest = uri[5:]
        if '@' in rest:
            if '#' in rest:
                rest, tag = rest.split('#', 1)
                tag = unquote(tag)
            else:
                tag = None
            auth, host_port = rest.split('@', 1)
            method, password = auth.split(':', 1)
            host, port = host_port.split(':', 1)
        else:
            if '#' in rest:
                main, tag = rest.split('#', 1)
                tag = unquote(tag)
            else:
                main = rest
                tag = None
            raw = base64.b64decode(main.split('?')[0] + '===').decode('utf-8')
            userinfo, host_port = raw.rsplit('@', 1)
            method, password = userinfo.split(':', 1)
            host, port = host_port.split(':', 1)
        return {
            'type': 'ss',
            'server': host,
            'port': int(port),
            'method': method,
            'password': password,
            'name': tag or f"ss_{host}"
        }
    except Exception:
        return None


def parse_socks(uri):
    # socks://[username:password@]host:port
    url = urlparse(uri)
    username = url.username or ''
    password = url.password or ''
    server = url.hostname
    port = url.port
    tag = unquote(url.fragment) if url.fragment else f"socks_{server}"
    return {
        'type': 'socks',
        'server': server,
        'port': int(port),
        'username': username,
        'password': password,
        'name': tag
    }


def parse_proxy_line(line):
    if line.startswith('vmess://'):
        return parse_vmess(line)
    elif line.startswith('vless://'):
        return parse_vless(line)
    elif line.startswith('trojan://'):
        return parse_trojan(line)
    elif line.startswith('ss://'):
        return parse_ss(line)
    elif line.startswith('socks://'):
        return parse_socks(line)
    else:
        return None


# --- CONFIG PARSING/RENDER ---
def read_yaml_file(yaml_path):
    with open(yaml_path, 'r', encoding='utf-8') as f:
        yaml_ = YAML()
        content = yaml_.load(f)
    return content


def write_yaml_file(yaml_obj, yaml_path):
    with open(yaml_path, 'w', encoding='utf-8') as f:
        yaml_ = YAML()
        yaml_.default_flow_style = False
        yaml_.dump(yaml_obj, f)


def read_json_file(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def write_json_file(obj, path):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


# ---- INJECTION LOGIC ----
def update_clash_proxies(clash_cfg, proxies):
    # Replace the list in 'proxies' with ours, unless you want to append.
    clash_cfg['proxies'] = [proxy_to_clash(p) for p in proxies]
    # Update 'proxy-groups' membership, e.g. add all new proxies to AUTO, select, etc.
    groupkeys = ['proxies', 'proxy', 'select', 'relay', 'url-test']
    for g in clash_cfg.get('proxy-groups', []):
        if g['type'] in ('select', 'url-test') and 'proxies' in g:
            for px in clash_cfg['proxies']:
                if px['name'] not in g['proxies']:
                    g['proxies'].append(px['name'])
    return clash_cfg


def proxy_to_clash(proxy):
    # Map internal proxy to Clash Meta format
    if proxy['type'] == 'vmess':
        return {
            'name': proxy['name'],
            'type': 'vmess',
            'server': proxy['server'],
            'port': proxy['port'],
            'uuid': proxy['uuid'],
            'alterId': int(proxy.get('alterId', '0')),
            'cipher': proxy.get('cipher', 'auto'),
            'tls': proxy['tls'],
            'network': proxy.get('network', 'tcp'),
        }
    elif proxy['type'] == 'vless':
        return {
            'name': proxy['name'],
            'type': 'vless',
            'server': proxy['server'],
            'port': proxy['port'],
            'uuid': proxy['uuid'],
            'encryption': proxy['encryption'],
            'flow': proxy.get('flow', ''),
            'network': proxy.get('network', 'tcp'),
            'tls': proxy['tls'],
        }
    elif proxy['type'] == 'trojan':
        return {
            'name': proxy['name'],
            'type': 'trojan',
            'server': proxy['server'],
            'port': proxy['port'],
            'password': proxy['password'],
        }
    elif proxy['type'] == 'ss':
        return {
            'name': proxy['name'],
            'type': 'ss',
            'server': proxy['server'],
            'port': proxy['port'],
            'cipher': proxy['method'],
            'password': proxy['password']
        }
    elif proxy['type'] == 'socks':
        out = {
            'name': proxy['name'],
            'type': 'socks5',
            'server': proxy['server'],
            'port': proxy['port'],
        }
        if proxy['username']:
            out['username'] = proxy['username']
        if proxy['password']:
            out['password'] = proxy['password']
        return out
    else:
        return None


def update_singbox_outbounds(sj, proxies):
    new_outbounds = []
    tagset = set()
    for p in proxies:
        sbo = proxy_to_singbox(p)
        if sbo['tag'] in tagset:
            continue
        new_outbounds.append(sbo)
        tagset.add(sbo['tag'])
    # Replace any proxies originally with same tag/type
    sj['outbounds'] = [o for o in sj['outbounds'] if o.get('tag', '') not in tagset]
    sj['outbounds'] += new_outbounds
    # Optionally update relay/group
    for o in sj['outbounds']:
        if o['type'] == 'selector' and 'outbounds' in o:
            # Add all new tags except duplicates
            for t in tagset:
                if t not in o['outbounds']:
                    o['outbounds'].append(t)
    return sj


def proxy_to_singbox(proxy):
    tag = proxy['name']
    if proxy['type'] == 'vmess':
        return {
            'type': 'vmess',
            'tag': tag,
            'server': proxy['server'],
            'server_port': proxy['port'],
            'uuid': proxy['uuid'],
            'alter_id': int(proxy.get('alterId', '0')),
            'network': proxy.get('network', 'tcp'),
            'tls': proxy.get('tls', False),
        }
    elif proxy['type'] == 'vless':
        return {
            'type': 'vless',
            'tag': tag,
            'server': proxy['server'],
            'server_port': proxy['port'],
            'uuid': proxy['uuid'],
            'encryption': proxy['encryption'],
            'flow': proxy.get('flow', ''),
            'network': proxy.get('network', 'tcp'),
            'tls': proxy['tls']
        }
    elif proxy['type'] == 'trojan':
        return {
            'type': 'trojan',
            'tag': tag,
            'server': proxy['server'],
            'server_port': proxy['port'],
            'password': proxy['password'],
        }
    elif proxy['type'] == 'ss':
        return {
            'type': 'shadowsocks',
            'tag': tag,
            'server': proxy['server'],
            'server_port': proxy['port'],
            'method': proxy['method'],
            'password': proxy['password'],
        }
    elif proxy['type'] == 'socks':
        ob = {
            'type': 'socks',
            'tag': tag,
            'server': proxy['server'],
            'server_port': proxy['port'],
        }
        if proxy['username']:
            ob['username'] = proxy['username']
        if proxy['password']:
            ob['password'] = proxy['password']
        return ob
    else:
        return {}


# ------ MAIN ENTRYPOINT ------
if __name__ == '__main__':
    if len(sys.argv) != 6:
        print(
            "Usage: python sub2clash_singbox.py <sub_url> <clash_template.yaml> <singbox_template.json> <output_clash.yaml> <output_singbox.json>")
        sys.exit(1)
    (url, clash_tmpl, singbox_tmpl, out_clash, out_sb) = sys.argv[1:]

    print(f"[+] Download: {url}")
    lines = download_subscription(url)
    print(f"[+] {len(lines)} lines found in sub...")
    proxies = []
    for line in lines:
        px = parse_proxy_line(line)
        if px:
            proxies.append(px)
    print(f"[+] Parsed proxies: {len(proxies)}")

    # --- Handle Clash Meta YAML ---
    print(f"[~] Processing Clash...")
    clash_cfg = read_yaml_file(clash_tmpl)
    clash_cfg = update_clash_proxies(clash_cfg, proxies)
    write_yaml_file(clash_cfg, out_clash)
    print(f"[✓] Output Clash config: {out_clash}")

    # --- Handle Singbox JSON ---
    print(f"[~] Processing Singbox...")
    singbox_cfg = read_json_file(singbox_tmpl)
    singbox_cfg = update_singbox_outbounds(singbox_cfg, proxies)
    write_json_file(singbox_cfg, out_sb)
    print(f"[✓] Output Singbox config: {out_sb}")
    print("Done!")
