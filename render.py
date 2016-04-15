from jinja2 import Environment, FileSystemLoader

config = {
    'AUTHOR': 'April King',
    'SITENAME': 'HTTP Observatory',
    'VERSION': '1.0.0',
}

render_targets = ('index.html',
                  'analyze.html')

env = Environment(loader=FileSystemLoader('templates'))

for target in render_targets:
    template = env.get_template(target)
    with open('dist/' + target, mode='w') as f:
        f.write(template.render(**config))

