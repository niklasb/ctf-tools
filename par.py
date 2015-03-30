import threading

def iter_parallel(f, seq, n=10):
    sz = len(seq)
    tasks = list(range(sz))[::-1]
    mx = threading.Lock()
    res = [None]*sz
    def thread():
        while True:
            with mx:
                if not tasks:
                    break
                i = tasks.pop()
            x = f(i)
            with mx:
                res[i] = x
    threads = [threading.Thread(target=thread) for _ in range(min(n, sz))]
    for t in threads: t.start()
    for t in threads: t.join()
    return res
