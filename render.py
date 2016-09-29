import base64
import hashlib
import os
import os.path
import shutil

from jinja2 import Environment, FileSystemLoader

config = {
    'AUTHOR': 'April King',
    'SITENAME': 'Observatory by Mozilla',
    'VERSION': '1.0.9',

    'hashes': {
        'css': {},
        'js': {},
    },
}

css_paths = {
    'src': 'css',
    'dest': os.path.join('dist', 'css')
}

js_paths = {
    'src': 'js',
    'dest': os.path.join('dist', 'js')
}

# First, delete and then copy all the CSS and JS files
for path in [css_paths, js_paths]:
    # Delete the old ones
    files = os.listdir(path['dest'])
    for file in files:
        if file.startswith('httpobs'):
            os.remove(os.path.join(path['dest'], file))

    # Copy in the updated files
    files = os.listdir(path['src'])
    for file in files:
        (name, ext) = file.split('.')

        versioned_name = name + '-' + config['VERSION'] + '.' + ext

        shutil.copyfile(os.path.join(path['src'], file),
                        os.path.join(path['dest'], versioned_name))

# Get the sha256 of the javascript files and store it in the config file
files = os.listdir(js_paths['dest'])
for file in files:
    # ignore map files
    if file.endswith('.map'):
        continue

    print(file)
    hash = base64.b64encode(hashlib.sha256(open(os.path.join(js_paths['dest'], file), 'rb').read()).digest()).decode('ascii')
    short_name = '-'.join(file.split('-')[:-1])  # httpobs-utils-1.3.0.min.js -> httpobs-utils

    config['hashes']['js'][short_name] = 'sha256-' + hash

# Same with CSS
files = os.listdir(css_paths['dest'])
for file in files:
    hash = base64.b64encode(hashlib.sha256(open(os.path.join(css_paths['dest'], file), 'rb').read()).digest()).decode('ascii')
    short_name = '-'.join(file.split('-')[:-1])  # httpobs-utils-1.3.0.min.js -> httpobs-utils

    config['hashes']['css'][short_name] = 'sha256-' + hash

render_targets = os.listdir('templates')
render_targets.remove('base.html')
env = Environment(loader=FileSystemLoader('templates'))
for target in render_targets:
    template = env.get_template(target)
    with open('dist/' + target, mode='w') as f:
        f.write(template.render(**config))

