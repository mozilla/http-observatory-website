import base64
import hashlib
import os
import os.path
import shutil

from jinja2 import Environment, FileSystemLoader

config = {
    'AUTHOR': 'April King',
    'SITENAME': 'Observatory by Mozilla',

    'files': {}

}

css_paths = {
    'src': 'css',
    'dest': os.path.join('dist', 'css')
}

js_paths = {
    'src': 'js',
    'dest': os.path.join('dist', 'js')
}

# Delete the old files and then copy all the CSS and JS files in
for path in [css_paths, js_paths]:
    # Delete the old ones
    files = os.listdir(path['dest'])
    for file in files:
        os.remove(os.path.join(path['dest'], file))

    # Copy in the updated files
    files = os.listdir(path['src'])
    for file in files:
        # Get the hashes for the file
        hash = base64.b64encode(hashlib.sha256(
            open(os.path.join(path['src'], file), 'rb').read()).digest()).decode('ascii')
        urlsafe_hash = hash.replace('+', '-').replace('/', '_')

        name = '.'.join(file.split('.')[:-1])  # jquery-3.4.5.min.js -> jquery-3.4.5.min
        ext = file.split('.')[-1]

        # create the versioned file name
        versioned_name = name + '.' + urlsafe_hash + '.' + ext

        # Store the hashes and web safe file name in the config for template rendering
        config['files'][file] = {
            'hash': 'sha256-' + hash,
            'name': versioned_name
        }

        # copy the files into the distribution folder
        src_file = os.path.join(path['src'], file)
        dest_file = os.path.join(path['dest'], versioned_name)
        shutil.copyfile(src_file, dest_file)

render_targets = os.listdir('templates')
render_targets.remove('base.html')
env = Environment(loader=FileSystemLoader('templates'))
for target in render_targets:
    template = env.get_template(target)
    with open('dist/' + target, mode='w') as f:
        f.write(template.render(**config))

