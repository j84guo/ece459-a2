import subprocess

def load_test_cases(file_name='test_cases.txt'):
    test_cases = []
    with open(file_name) as f:
        while True:
            l = f.readline()
            if not l:
                break
            l = l.strip()
            if len(l) == 0:
                continue
            token = l
            secret = f.readline().strip()
            test_cases.append((token, secret))
    return test_cases

if __name__ == '__main__':
    test_cases = load_test_cases()
    subprocess.run(['cargo', 'build', '--release'])
    for bin in [
        # 'lab2',
        'shared-mem',
        # 'message-passing'
    ]:
        print('testing binary {}'.format(bin))
        for (token, secret) in test_cases:
            print('expecting {}, got '.format(secret))
            subprocess.run(['./target/release/{}'.format(bin), token, '{}'.format(len(secret))])

