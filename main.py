#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse, os, sys, socket, subprocess, hashlib, json, string

import iserver

version = 'ALPHA 0.1.0'

nulldevice = open(os.devnull, 'w')

script = '''
<script type="text/javascript" src="//cdnjs.cloudflare.com/ajax/libs/json3/3.3.2/json3.min.js"></script>
<script type="text/javascript">
    window.ekata_sfx = '///DATAURI///';
    window.ekata_uri = ( location.href.indexOf("?") === -1 ? 
        ( location.href.indexOf("#") === -1 ? 
            location.href + ekata_sfx :
            location.href.substring(0, location.href.indexOf("#")) + ekata_sfx 
        ) :
        location.href.substring(0, location.href.indexOf("?")) + ekata_sfx
    );
    
    window.ekata_data = [];
    
    function ekata_func(rjs) {
        if (rjs) eval(rjs);
        
        var x = new(this.XMLHttpRequest || ActiveXObject)('MSXML2.XMLHTTP.3.0');
        x.open('POST', ekata_uri, true);
        x.onreadystatechange = function () {
            if (x.readyState > 3) setTimeout(function(){ekata_func(x.responseText);}, 1);
        };
        x.send(JSON.stringify(ekata_data.splice(0, 4)));
        ekata_data = []; 
    }
    
    ekata_func();
</script>
'''

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('root', help='The root directory of the server.')
arg_parser.add_argument('-a', '--address', help='The address of the server.', default='localhost')
arg_parser.add_argument('-p', '--port', help='The port the server should run on.', default=80, type=int)
arg_parser.add_argument('-k', '--key', help='The SSL key for secure conections. (NYI)')
arg_parser.add_argument('-c', '--certificate', help='The SSL certificate for secure conections. (NYI)')
args = arg_parser.parse_args()

ii = None

try:
    subprocess.Popen(['sass', '--version'], stdout=nulldevice).communicate()
    subprocess.Popen(['scss', '--version'], stdout=nulldevice).communicate()
    sass_enabled = True
except OSError:
    sass_enabled = False
    
try:
    subprocess.Popen(['php', '--version'], stdout=nulldevice).communicate()
    php_enabled = True
except OSError:
    php_enabled = False

class Memory:
    def __init__(self):
        self.dict = {}
    
    def get(self, k, d=None):
        return self.dict.get(k, d)
    
    def set(self, k, v):
        self.dict[k] = v

class EkataInstance:
    def __init__(self, pgrm, conn):
        self.pgrm = pgrm
        self.ip = 0
        self.stack = []
        self.dead = False
        self.conn = conn
    
    def run(self):
        while 1:
            try:
                i = self.pgrm.objcode[self.ip]
            except IndexError:
                self.dead = True
                break
            
            try:
                j = self.pgrm.objcode[self.ip+1]
            except IndexError:
                pass
            
            if i == 'lit':
                self.stack.append(j)
                self.ip += 2
                continue
            
            if i == 'getglobmem':
                self.stack.append(gmem.get(j))
                self.ip += 2
                continue
            
            if i == 'setglobmem':
                gmem.set(j, self.stack.pop())
                self.ip += 2
                continue
            
            if i == 'pushjs':
                ekata_users[self.conn.get_cookie('usrid')].get('js').append(self.stack.pop())
                self.ip += 1
                continue
            
            if i == 'jmp':
                self.ip = j
                continue
            
            if i == 'jmpif':
                if self.stack.pop():
                    self.ip = j
                else:
                    self.ip += 2
                continue
            
            if i == 'dup':
                x = self.stack.pop()
                self.stack.append(x)
                self.stack.append(x)
                self.ip += 1
                continue
            
            if i == 'flip':
                x = self.stack.pop()
                y = self.stack.pop()
                self.stack.append(x)
                self.stack.append(y)
                self.ip += 1
                continue
            
            if i == '+':
                x = self.stack.pop()
                y = self.stack.pop()
                self.stack.append(y+x)
                self.ip += 1
                continue
            
            if i == '-':
                x = self.stack.pop()
                y = self.stack.pop()
                self.stack.append(y-x)
                self.ip += 1
                continue
            
            if i == 'repr':
                self.stack.append(repr(self.stack.pop()))
                self.ip += 1
                continue
            
            if i == 'pop':
                self.stack.pop()
                self.ip += 1
                continue
            
            if i == 'dblog':
                x = self.stack.pop()
                print('[%s %r]' % (type(x).__name__, x))
                self.ip += 1
                continue

class EkataProgram:
    def __init__(self, ln):
        self.code = ''
        self.ln = ln
    
    def compile_(self, page):
        global ii
        
        tokens = []
        
        def newToken(t, d=None):
            tokens.append((t, d, self.ln));
        
        i = 0
        while i < len(self.code):
            if self.code[i] == '\n': self.ln += 1
            
            if self.code[i] in string.whitespace:
                i += 1
                continue
            
            if self.code[i] in '"\'':
                q = self.code[i]
                s = ''
                i += 1
                while self.code[i] != q:
                    s += self.code[i]
                    i += 1
                i += 1
                newToken('lit', s)
                continue
            
            if self.code[i] in string.letters:
                s = ''
                while self.code[i] in string.letters + string.digits:
                    s += self.code[i]
                    i += 1
                if s in (
                         'debuglog',
                         'if'
                        ):
                    
                    newToken(s)
                else:
                    newToken('id', s)
                continue
            
            if self.code[i] in string.digits:
                s = ''
                while self.code[i] in string.letters + string.digits:
                    s += self.code[i]
                    i += 1
                newToken('lit', eval(s))
                continue
            
            for j in (
                      
                      '?', ':',
                      '#', '$', '.',
                      '=', '@', '*',
                      '+', '-', '/',
                     ):
            
                if self.code[i:].startswith(j):
                    newToken(j)
                    i += len(j)
                    break
            else:
                raise ValueError("Unexpected character '%s' on line %i, aborting!" % (self.code[i], self.ln))
        
        newToken('EOF')
        
        ii = 0
        
        def N():
            global ii
            ii += 1
            return tokens[ii-1]
        
        def A(t):
            return t == tokens[ii][0]
        
        def E(t):
            if A(t): return N()
            raise TypeError('Unexpected token %s on line %i, expected %s. Aborting!' % (tokens[ii][0], tokens[ii][2], t))
        
        def AE(t):
            if A(t): return N()
        
        def parseStmts():
            s = parseStmt()
            ss = []
            while s:
                ss.append(s)
                s = parseStmt()
            return ('block', ss)
        
        def parseStmt():
            
            if AE('debuglog'):
                return ('debuglog', parseExprBase())
            
            if A('EOF'): return None
            
            return ('do', parseExprBase())
        
        def parseExprBase():
            return parseExprAsgn()
        
        def parseExprAsgn():
            c = parseExprTnry()
            if AE('='):
                return ('asgn', c, parseExprAsgn())
            return c
        
        def parseExprTnry():
            c = parseExprAS()
            if AE('?'):
                y = parseExprBase()
                E(':')
                n = parseExprBase()
                return ('tnry', c, y, n)
            return c
        
        def parseExprAS():
            c = parseExprAttr()
            while A('+') or A('-'):
                op = N()[0]
                c = ('binop', op, c, parseExprAttr())
            return c
        
        def parseExprAttr():
            c = parseExprLit()
            while A('.'):
                if AE('.'):
                    c = ('getattr', c, ('lit', E('id')[1]))
            return c
        
        def parseExprLit():
            
            if AE('@'):
                if AE('@'):
                    return ('globvar', E('id')[1])
                return ('pagevar', E('id')[1])
            
            if AE('#'):
                return ('elbyid', E('id')[1])
            
            if A('lit'): return ('lit', N()[1])
            
            E('Expression')
        
        root = parseStmts()
        
        E('EOF')
        
        self.objcode = []
        
        def genObjCode(node):
            
            if node[0] == 'block':
                for i in node[1]:
                    genObjCode(i)
            
            elif node[0] == 'do':
                genObjCode(node[1])
                self.objcode.append('pop')
            
            elif node[0] == 'debuglog':
                genObjCode(node[1])
                self.objcode.append('dblog')
            
            elif node[0] == 'lit':
                self.objcode.extend(['lit', node[1]])
            
            elif node[0] == 'globvar':
                self.objcode.extend(['getglobmem', node[1]])
            
            elif node[0] == 'binop':
                genObjCode(node[2])
                genObjCode(node[3])
                self.objcode.append(node[1])
            
            elif node[0] == 'tnry':
                genObjCode(node[1])
                self.objcode.extend(['jmpif', None])
                jmpiffrom = len(self.objcode)-1
                genObjCode(node[3])
                self.objcode.extend(['jmp', None])
                jmpfrom = len(self.objcode)-1
                self.objcode[jmpiffrom] = len(self.objcode)
                genObjCode(node[2])
                self.objcode[jmpfrom] = len(self.objcode)
                
            
            elif node[0] == 'asgn':
                genObjCode(node[2])
                self.objcode.append('dup')
                if node[1][0] == 'globvar':
                    self.objcode.extend(['setglobmem', node[1][1]])
                elif node[1][0] == 'getattr' and node[1][1][0] == 'elbyid':
                    self.objcode.extend(['repr', 'lit', 'document.getElementById(%r)[' % node[1][1][1]])
                    genObjCode(node[1][2])
                    self.objcode.extend(['repr', 'lit', ']=', '+', '+', 'flip', '+', 'lit', ';', '+', 'pushjs'])
                    
                else:
                    raise TypeError('Invalid assignment to '+node[1][0])
            
        genObjCode(root)
        
    def run(self, conn):
        ekata_instances.append(EkataInstance(self, conn))

class EkataPage:
    def __init__(self, code, path, md5):
        self.path = path
        self.md5 = md5
        
        self.pgrms = {}
        self.html = ''
        i = 0
        ln = 1
        while i < len(code):
            if code[i] == '\n': ln += 1
            if code[i:i+3] == '<<<':
                self.html += 'ekata_data.push({run: %i});' % i
                pgrm = self.pgrms[i] = EkataProgram(ln)
                i += 3
                while i < len(code):
                    if code[i] == '\n': ln += 1
                    if code[i:i+3] == '>>>':
                        i += 3
                        pgrm.compile_(self)
                        break
                    pgrm.code += code[i]
                    i += 1
            self.html += code[i]
            i += 1
        
        self.html = self.html.replace('<ekata>', script)

try:
    iserver.bind((args.address, args.port))
except OverflowError:
    sys.stderr.write('Error: Port must be in range 0 to 65535.\n')
    sys.exit(1)
except socket.error as e:
    sys.stderr.write('Error: %s.\n' % e)
    sys.exit(1)

gmem = Memory()

def run_ekata():
    i = len(ekata_instances)
    while i:
        i -= 1
        ekata_instances[i].run()
        if ekata_instances[i].dead:
            del ekata_instances[i]

print('एकता (ekata) version ' + version)
print('Running on %s:%i' % (args.address, args.port))
print('SASS: %sabled' % (('dis','en')[sass_enabled]))
print('PHP: %s' % (('disabled','limited')[php_enabled]))

ekata_pages = {}
ekata_instances = []
ekata_users = {}

if 'onload.ekatascr' in os.listdir(args.root):
    olf = open(os.path.join(args.root, 'onload.ekatascr'))
    ol = olf.read()
    olf.close()
    pgrm = EkataProgram(0)
    pgrm.code = ol
    pgrm.compile_(None)
    pgrm.run(None)
    while ekata_instances: run_ekata()

while True:
    try:
        conn = iserver.get_next_connection()
    except KeyboardInterrupt:
        print('Interrupted. Shutting down.')
        sys.exit(130)
    if not conn.path.endswith('///DATAURI///'): print('%s\t%s' % (conn.type, conn.path))
    if not conn.get_cookie('usrid') or conn.get_cookie('usrid') not in ekata_users.keys():
        usrid = os.urandom(64).encode('hex')
        conn.set_cookie('usrid', usrid, http_only=True, expires='Tue, 19 Jan 2038 00:00:00 GMT', path='/')
        ekata_users[usrid] = Memory()
        ekata_users[usrid].set('js', [])
    spath = conn.path.split('/')
    if spath.count('..') > len(spath) - spath.count('..'):
        conn.error(403)
        continue
        
    fpath = os.path.join(*([args.root] + spath))
    
    
    if os.path.isdir(fpath):
        if fpath[-1] == '/':
            flag = False
            for pindex in ('index.htm', 'index.html','index.ekata','index.php'):
                if pindex in os.listdir(fpath):
                    conn.redirect(fpath + pindex, 301)
                    flag = True
                    break
            
            if flag: continue
                
        else:
            conn.redirect(fpath + '/', 301)
            continue
    
    if sass_enabled:
        is_sass = False
        if fpath.lower().endswith('.sass'):
            cmd = 'sass'
            is_sass = True
        elif fpath.lower().endswith('.scss'):
            cmd = 'scss'
            is_sass = True
        if is_sass:
            ssf = open(fpath, 'r')
            ss = ssf.read()
            ssf.close()
            res = subprocess.Popen([cmd, '-t', 'compressed'], stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate(ss)[0]
            conn.respond(res, mimetype='text/css')
            continue
    
    if php_enabled and fpath.lower().endswith('.php'):
        pf = open(fpath, 'r')
        p = ssf.read()
        pf.close()
        res = subprocess.Popen(['php'], stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate(p)[0]
        conn.respond(res)
        continue
    
    if fpath.lower().endswith('.ekata'):
        ekf = open(fpath, 'r')
        ek = ekf.read()
        ekf.close()
        ekmd5 = hashlib.md5(ek).digest()
        if fpath not in ekata_pages.keys() or ekmd5 != ekata_pages[fpath].md5:
            page = ekata_pages[fpath] = EkataPage(ek, path=fpath, md5=ekmd5)
        else:
            page = ekata_pages[fpath]
        conn.respond(page.html)
        continue
    
    if conn.path.endswith('///DATAURI///'):
        fpath = fpath[:-9]
        if fpath in ekata_pages.keys():
        
            run_ekata()
        
            page = ekata_pages[fpath]
            data = json.loads(conn.body)
            
            for datum in data:
                if 'run' in datum.keys():
                    page.pgrms[datum['run']].run(conn)
            
            mem = ekata_users[conn.get_cookie('usrid')]
            
            if mem.get('js'):
                resp = '(function(){'
                
                for js in mem.get('js'):
                    resp += js
                
                resp += '})()'
            else:
                resp = ''
            conn.respond(resp, mimetype='text/javascript')
            continue
    
    conn.respond_with_file(fpath)
