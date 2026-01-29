from datetime import datetime
import arrow
import base64
import cgi
import gevent
import tempfile
import gzip
import json
import math
import os
from io import BytesIO
import pickle
import logging
from urllib.parse import unquote
import tempfile
from urllib.parse import parse_qs
from email import message_from_binary_file
from email.parser import BytesParser



from aj.api.http import BaseHttpHandler
import aj

def _validate_origin(env):
    protocol = 'https' if env['SSL'] else 'http'
    valid_origin = aj.config.data['trusted_domains'] + [f'{protocol}://{env["HTTP_HOST"]}']
    request_origin = env.get('HTTP_ORIGIN', '').strip('/')
    if request_origin:
        return request_origin in valid_origin
    return True


class HttpRoot():
    """
    A root WSGI middleware object that creates the :class:`HttpContext` and dispatches
    it to an HTTP handler.

    :param handler: next middleware handler
    :type  handler: :class:`aj.api.http.BaseHttpHandler`
    """

    def __init__(self, handler):
        self.handler = handler

    def dispatch(self, env, start_response):
        """
        Dispatches the WSGI request
        """
        if not _validate_origin(env):
            start_response('403 Invalid Origin', [])
            return ''

        http_context = HttpContext(env, start_response)
        http_context.prefix = env.get('HTTP_X_URL_PREFIX', '')
        if http_context.prefix:
            if http_context.path.startswith(http_context.prefix):
                http_context.path = http_context.path[len(http_context.prefix):] or '/'
            else:
                http_context.respond(400)
                http_context.run_response()
                return [b'Invalid URL Prefix']

        content = self.handler.handle(http_context)

        if http_context.prefix:
            for index, header in enumerate(http_context.headers):
                if header[0] == 'Location':
                    http_context.headers[index] = (header[0], http_context.prefix + header[1])

        http_context.run_response()
        gevent.sleep(0)
        return content


class HttpMiddlewareAggregator(BaseHttpHandler):
    """
    Stacks multiple HTTP handlers together in a middleware fashion.

    :param stack: handler list
    :type  stack: list(:class:`aj.api.http.BaseHttpHandler`)
    """

    def __init__(self, stack):
        self.stack = stack

    def handle(self, http_context):
        for middleware in self.stack:
            output = middleware.handle(http_context)
            if output is not None:
                return output

# class CGIFieldStorage(cgi.FieldStorage):
#     # Fix cgi bug when a put request does not have a content-disposition
#     # See https://github.com/python/cpython/issues/71964
#     # TODO : cgi module will be deprecated in Python 3.11
#
#     def make_file(self, binary=None):
#         """
#         Always open a tempfile as binary
#         """
#         return tempfile.TemporaryFile("wb+")

class CGIFieldStorage:
    """
    Replacement for cgi.FieldStorage for handling form data and file uploads.
    Compatible with Python 3.13+
    """

    def __init__(self, fp=None, headers=None, environ=None):
        self.file = fp
        self.headers = headers or {}
        self.environ = environ or {}
        self.list = []
        self.type = None
        self.type_options = {}

        if headers:
            content_type = headers.get('Content-Type', '')
            if content_type:
                self._parse_content_type(content_type)

        if fp:
            self._parse_data(fp)

    def _parse_content_type(self, content_type):
        """Parse content type header"""
        from email.message import EmailMessage
        msg = EmailMessage()
        msg['content-type'] = content_type
        self.type = msg.get_content_type()
        # Get parameters like boundary
        if hasattr(msg['content-type'], 'params'):
            self.type_options = dict(msg['content-type'].params)

    def _parse_data(self, fp):
        """Parse the form data"""
        if self.type == 'multipart/form-data':
            self._parse_multipart(fp)
        elif self.type == 'application/x-www-form-urlencoded':
            self._parse_urlencoded(fp)

    def _parse_multipart(self, fp):
        """Parse multipart form data"""
        boundary = self.type_options.get('boundary', '').encode()
        if not boundary:
            return

        # Read and parse multipart data
        data = fp.read()
        parts = data.split(b'--' + boundary)

        for part in parts[1:-1]:  # Skip first empty and last closing boundary
            if not part.strip():
                continue

            # Split headers and body
            header_end = part.find(b'\r\n\r\n')
            if header_end == -1:
                header_end = part.find(b'\n\n')
                if header_end == -1:
                    continue

            header_data = part[:header_end]
            body_data = part[header_end + 4:].rstrip(b'\r\n')

            # Parse headers
            parser = BytesParser()
            headers = parser.parsebytes(header_data + b'\r\n\r\n')

            # Create field item
            item = FieldItem()
            item.headers = dict(headers.items())

            # Parse Content-Disposition
            content_disp = headers.get('Content-Disposition', '')
            if content_disp:
                item.name = self._get_disposition_name(content_disp)
                item.filename = self._get_disposition_filename(content_disp)

            if item.filename:
                # File upload
                item.file = self.make_file()
                item.file.write(body_data)
                item.file.seek(0)
            else:
                # Regular field
                item.value = body_data.decode('utf-8', errors='replace')

            self.list.append(item)

    def _parse_urlencoded(self, fp):
        """Parse URL-encoded form data"""
        data = fp.read()
        if isinstance(data, bytes):
            data = data.decode('utf-8', errors='replace')

        parsed = parse_qs(data, keep_blank_values=True)

        for name, values in parsed.items():
            for value in values:
                item = FieldItem()
                item.name = name
                item.value = value
                self.list.append(item)

    def _get_disposition_name(self, disposition):
        """Extract name from Content-Disposition header"""
        from email.message import EmailMessage
        msg = EmailMessage()
        msg['content-disposition'] = disposition
        params = dict(msg['content-disposition'].params) if hasattr(msg['content-disposition'], 'params') else {}
        return params.get('name', '')

    def _get_disposition_filename(self, disposition):
        """Extract filename from Content-Disposition header"""
        from email.message import EmailMessage
        msg = EmailMessage()
        msg['content-disposition'] = disposition
        params = dict(msg['content-disposition'].params) if hasattr(msg['content-disposition'], 'params') else {}
        return params.get('filename', '')

    def make_file(self, binary=None):
        """
        Always open a tempfile as binary
        Fix for PUT requests without content-disposition
        """
        return tempfile.TemporaryFile("wb+")

    def __getitem__(self, key):
        """Get field by name"""
        for item in self.list:
            if item.name == key:
                return item
        raise KeyError(key)

    def getvalue(self, key, default=None):
        """Get value of a field"""
        try:
            item = self[key]
            return item.value if hasattr(item, 'value') else default
        except KeyError:
            return default

    def getlist(self, key):
        """Get all values for a field name"""
        return [item.value for item in self.list if item.name == key and hasattr(item, 'value')]


class FieldItem:
    """Represents a single form field or file upload"""

    def __init__(self):
        self.name = None
        self.value = None
        self.filename = None
        self.file = None
        self.headers = {}


class HttpContext():
    """
    Instance of :class:`HttpContext` is passed to all HTTP handler methods

    .. attribute:: env

        WSGI environment dict

    .. attribute:: path

        Path segment of the URL

    .. attribute:: method

        Request method

    .. attribute:: headers

        List of HTTP response headers

    .. attribute:: body

        Request body

    .. attribute:: response_ready

        Indicates whether a HTTP response has already been submitted in this context

    .. attribute:: query

        HTTP query parameters
    """

    def __init__(self, env, start_response=None):
        self.start_response = start_response
        self.env = env
        self.path = env['PATH_INFO']
        self.headers = []
        self.response_ready = False
        self.status = None
        self.body = None
        self.query = None
        self.form_cgi_query = None
        self.url_cgi_query = None
        self.prefix = None
        self.method = self.env['REQUEST_METHOD'].upper()

        self.env.setdefault('QUERY_STRING', '')
        if self.method in ['POST', 'PUT', 'PATCH']:
            ctype = self.env.get('CONTENT_TYPE', 'application/x-www-form-urlencoded')
            if 'wsgi.input' in self.env:
                self.body = self.env['wsgi.input'].read()
                if ctype.startswith('application/x-www-form-urlencoded') or \
                        ctype.startswith('multipart/form-data'):
                    if isinstance(self.body, str):
                        # Avoid compatibility problem
                        logging.warning("Body converted to bytes!")
                        self.body = self.body.encode()
                    self.form_cgi_query = CGIFieldStorage(
                        fp=BytesIO(self.body),
                        environ=self.env,
                        keep_blank_values=1
                    )

        elif self.method in ['OPTIONS', 'PROPFIND', 'UPLOAD']:
            # Read other request's body (like XML)
            if 'wsgi.input' in self.env:
                self.body = self.env['wsgi.input'].read()

        else:
            # prevent hanging on weird requests
            self.env['REQUEST_METHOD'] = 'GET'
            self.env['REQUEST_METHOD'] = self.method

        self.url_cgi_query = cgi.FieldStorage(
            environ={
                'QUERY_STRING': unquote(self.env['QUERY_STRING'], encoding='latin-1')
            },
            keep_blank_values=1
        )

        self.query = {}
        if hasattr(self.form_cgi_query, 'list') and self.form_cgi_query.list is not None:
            self.query.update({k:self.form_cgi_query[k].value for k in self.form_cgi_query})
        if self.url_cgi_query:
            self.query.update({k:self.url_cgi_query[k].value for k in self.url_cgi_query})

    def json_body(self):
        return json.loads(self.body.decode('utf-8'))

    def dump_env(self):
        print('\n'.join(f'{x} = {self.env[x]}') for x in sorted(list(self.env)))

    def get_cleaned_env(self):
        env = self.env.copy()
        for k in list(env):
            # pylint: disable=W1504
            if type(env[k]) not in (str, bytes, list, dict, bool, type(None), int):
                del env[k]
        return env

    def serialize(self):
        return base64.b64encode(pickle.dumps({
            'env': self.get_cleaned_env(),
            'path': self.path,
            'headers': self.headers,
            'body': base64.b64encode(self.body) if self.body else None,
            'query': self.query,
            'prefix': self.prefix,
            'method': self.method,
        }, protocol=0))

    @classmethod
    def deserialize(cls, data):
        data = pickle.loads(base64.b64decode(data))
        self = cls(data['env'])
        self.path = data['path']
        self.headers = data['headers']
        self.body = base64.b64decode(data['body']) if data['body'] else None
        self.query = data['query']
        self.prefix = data['prefix']
        self.method = data['method']
        return self

    def add_header(self, key, value):
        """
        Adds a given HTTP header to the response

        :param key: header name
        :type  key: str
        :param value: header value
        :type  value: str
        """
        self.headers += [(key, value)]

    def remove_header(self, key):
        """
        Removed a given HTTP header from the response

        :param key: header name
        :type  key: str
        """
        self.headers = [h for h in self.headers if h[0] != key]

    def fallthrough(self, handler):
        """
        Executes a ``handler`` in this context

        :type handler: :class:`aj.api.http.BaseHttpHandler`
        :returns: handler-supplied output
        """
        return handler.handle(self)

    def run_response(self):
        """
        Finalizes the response and runs WSGI's ``start_response()``.
        """
        if not self.response_ready:
            raise Exception('Response not created yet!')

        status = self.status
        if isinstance(status, int):
            status = f'{status} '
        self.start_response(
            str(status),
            [(str(x), str(y)) for x, y in self.headers]
        )

    def respond(self, status):
        """
        Creates a response with given HTTP status line

        :type status: str
        """
        self.status = status
        self.response_ready = True

    def respond_ok(self):
        """
        Creates a ``HTTP 200 OK`` response
        """
        self.respond('200 OK')

    def respond_server_error(self):
        """
        Returns a HTTP ``500 Server Error`` response
        """
        self.respond('500 Server Error')
        return [b'Server Error']


    def respond_unauthenticated(self):
        """
        Returns a HTTP ``401 Unauthenticated`` response
        """
        self.respond('401 Unauthenticated')
        return [b'Unauthenticated']

    def respond_forbidden(self):
        """
        Returns a HTTP ``403 Forbidden`` response
        """
        self.respond('403 Forbidden')
        return [b'Forbidden']

    def respond_not_found(self):
        """
        Returns a ``HTTP 404 Not Found`` response
        """
        self.respond('404 Not Found')
        return [b'Not Found']

    def respond_bad_request(self):
        """
        Returns a ``HTTP 400 Bad Request`` response
        """
        self.respond('400 Bad Request')
        return [b'Bad Request']

    def redirect(self, location):
        """
        Returns a ``HTTP 302 Found`` redirect response with given ``location``

        :type location: str
        """
        self.add_header('Location', location)
        self.respond('302 Found')
        return ''

    def gzip(self, content, compression=6):
        """
        Returns a GZip compressed response with given ``content`` and correct headers

        :type content: str
        :param compression: compression level from 0 to 9
        :type  compression: int
        :rtype: str
        """
        io = BytesIO()
        gz = gzip.GzipFile('', 'wb', compression, io)
        gz.write(content)
        gz.close()
        compressed = io.getvalue()

        self.add_header('Content-Length', str(len(compressed)))
        self.add_header('Content-Encoding', 'gzip')
        self.respond_ok()

        return compressed

    def file(self, path, stream=False, inline=False, name=None):
        """
        Returns a GZip compressed response with content of file located in ``path`` and correct headers

        :type path: str
        :type stream: bool
        """

        # Block path traversal
        if '..' in path:
            self.respond_forbidden()
            return

        if not os.path.isfile(path):
            self.respond_not_found()
            return

        content_types = {
            '.html': 'text/html',
            '.css': 'text/css',
            '.js': 'application/javascript',
            '.png': 'image/png',
            '.jpg': 'image/jpeg',
            '.svg': 'image/svg+xml',
            '.woff': 'application/x-font-woff',
            '.pdf': 'application/pdf',
        }

        ext = os.path.splitext(path)[1]
        if ext in content_types:
            self.add_header('Content-Type', content_types[ext])
        else:
            self.add_header('Content-Type', 'application/octet-stream')

        mtime = datetime.utcfromtimestamp(math.trunc(os.path.getmtime(path)))

        rtime = self.env.get('HTTP_IF_MODIFIED_SINCE', None)
        if rtime:
            try:
                rtime = datetime.strptime(rtime, '%a, %b %d %Y %H:%M:%S GMT')
                if mtime <= rtime:
                    self.respond('304 Not Modified')
                    return
            except Exception as e:
                pass

        http_range = self.env.get('HTTP_RANGE', None)
        range_from = range_to = None
        if http_range and http_range.startswith('bytes'):
            rsize = os.stat(path).st_size
            range_from, range_to = http_range.split('=')[1].split('-')
            range_from = int(range_from) if range_from else 0
            range_to = int(range_to) if range_to else (rsize - 1)
        else:
            range_from = 0
            range_to = 999999999

        # Ensure datetime don't use locale with non-latin chars
        last_modified_date = arrow.get(mtime, 'GMT').format('ddd, MMM DD YYYY HH:mm:ss ZZZ')
        self.add_header('Last-Modified', last_modified_date)
        self.add_header('Accept-Ranges', 'bytes')

        name = name or os.path.split(path)[-1].encode()

        if inline:
            self.add_header('Content-Disposition', (f'inline; filename={name.decode()}'))
        else:
            self.add_header('Content-Disposition', (f'attachment; filename={name.decode()}'))

        if stream:
            if range_from:
                self.add_header('Content-Length', str(range_to - range_from + 1))
                self.add_header('Content-Range',
                                f'bytes {range_from:d}-{range_to:d}/{rsize}')
                self.respond('206 Partial Content')
            else:
                self.respond_ok()
            fd = os.open(path, os.O_RDONLY)
            os.lseek(fd, range_from or 0, os.SEEK_SET)
            bufsize = 100 * 1024
            read = range_from
            buf = 1
            while buf:
                buf = os.read(fd, bufsize)
                gevent.sleep(0)
                if read + len(buf) > range_to:
                    buf = buf[:range_to + 1 - read]
                yield buf
                read += len(buf)
                if read >= range_to:
                    break
            os.close(fd)
        else:
            with open(path, 'rb') as file_to_serve:
                content = file_to_serve.read()
            yield self.gzip(content)
