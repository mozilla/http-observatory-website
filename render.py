import base64
import hashlib
import os
import os.path

from jinja2 import Environment, FileSystemLoader

config = {
    'AUTHOR': 'April King',
    'SITENAME': 'Mozilla Observatory',
    'VERSION': '1.0.0',

    'hashes': {
        'css': {},
        'js': {},
    },
}

css_path = os.path.join('dist', 'css')
js_path = os.path.join('dist', 'js')

render_targets = ('index.html',
                  'analyze.html')

env = Environment(loader=FileSystemLoader('templates'))

# Get the sha256 of the javascript files and store it in the config file
files = os.listdir(js_path)
for file in files:
    # ignore map files
    if file.endswith('.map'):
        continue

    print(file)
    hash = base64.b64encode(hashlib.sha256(open(os.path.join(js_path, file), 'rb').read()).digest()).decode('ascii')
    short_name = '-'.join(file.split('-')[:-1])  # httpobs-utils-1.3.0.min.js -> httpobs-utils

    config['hashes']['js'][short_name] = 'sha256-' + hash

# Same with CSS
files = os.listdir(css_path)
for file in files:
    hash = base64.b64encode(hashlib.sha256(open(os.path.join(css_path, file), 'rb').read()).digest()).decode('ascii')
    short_name = '-'.join(file.split('-')[:-1])  # httpobs-utils-1.3.0.min.js -> httpobs-utils

    config['hashes']['css'][short_name] = 'sha256-' + hash

print(config)


for target in render_targets:
    template = env.get_template(target)
    with open('dist/' + target, mode='w') as f:
        f.write(template.render(**config))

