from livereload import Server
from subprocess import call


def regen():
    print('Regenerating via "make publish"')
    call(['make', 'publish'])


server = Server()
server.watch('templates/*', regen)
server.watch('dist/css/*', regen)
server.watch('dist/js/*', regen)


server.serve(root='dist', port=5500, liveport=35729)
