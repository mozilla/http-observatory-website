from livereload import Server
from subprocess import call


def regen():
    print('Regenerating via "make publish"')
    call(['make', 'publish'])


server = Server()
server.watch('templates/*', regen, delay=1)
server.watch('dist/js/*', regen, delay=1)
server.watch('dist/css/*', regen, delay=1)

server.serve(root='dist', port=5500, liveport=35729)
