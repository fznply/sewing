sewing
======
- sewing is a nginx http module.
- sewing depends on epoll, only work on linux.
- one nginx-worker-process <--> one sewing-work-thread <--> many/none sewing-task-threads.

suitable scene
======
- use coroutine library (libgo or libco) in sewing-work-thread.
- use block io in sewing-task-threads, but not block nginx worker process.
- not good at or not easy to write non-block handler in nginx main loop.

design mind
======
- sewing-work-thread use socketpair connection communicate with nginx-worker-process.
- sewing-work-thread use socketpair connection communicate with  sewing-task-threads.
- use socketpair connection to pass through http_request pointer, not http_request object.

usage
======
1. install sewing/nginx (default install home dir), please exec command as bellow:

	```
    bash install_nginx_with_sewing.sh
    ```

2. config sewing/nginx.

	```
	# In Nginx Location Conf, Add Bellow:
	sewing demo
	```

3. sewing/nginx will response http request on the location.
