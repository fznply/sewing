#!/bin/bash
cd `dirname $0`
SEWING_MODULE_ROOT=`pwd`
NGINX_ROOT=$HOME

cd third

mkdir -p $NGINX_ROOT/nginx/logs
mkdir -p $NGINX_ROOT/nginx/tmp
mkdir -p $NGINX_ROOT/nginx/fastcgi_cache

tar xzf nginx-1.12.0.tar.gz
tar xzf ngx_devel_kit-0.3.0.tar.gz
cd nginx-1.12.0

CFLAGS="-g -O0"
#CFLAGS="-O3"
CFLAGS="$CFLAGS" ./configure --prefix=$NGINX_ROOT/nginx --pid-path=$NGINX_ROOT/nginx/run/nginx.pid --error-log-path=$NGINX_ROOT/nginx/logs/error.log --http-log-path=$NGINX_ROOT/nginx/logs/access.log --with-http_stub_status_module --with-http_gzip_static_module --with-http_realip_module --with-http_ssl_module --with-debug --http-proxy-temp-path=$NGINX_ROOT/nginx/tmp/proxy_temp --http-fastcgi-temp-path=$NGINX_ROOT/nginx/tmp/fastcgi_temp --http-uwsgi-temp-path=$NGINX_ROOT/nginx/tmp/uwsgi_temp --http-scgi-temp-path=$NGINX_ROOT/nginx/tmp/scgi_temp --http-client-body-temp-path=$NGINX_ROOT/nginx/tmp/client_body_temp --with-http_sub_module --with-threads --with-ld-opt=-Wl,-rpath,$NGINX_ROOT/nginx/LuaJIT/lib --with-cc-opt=-Wno-error --add-module="$SEWING_MODULE_ROOT/third/ngx_devel_kit-0.3.0" --add-module="$SEWING_MODULE_ROOT/module"
make
make install
