import os
from urllib.parse import urlparse
import click

import initdatabase

try:
    import config
except ImportError:
    print('It seems like this is the first time running the server.')
    print('First let us generate a proper configuration file.')
    try:
        from generateconfig import generate_config
        generate_config()
        import config
        print('Initializing database "%s".' % config.SQLALCHEMY_DATABASE_URI)
        initdatabase.init_database()
    except Exception as e:
        print(e)
        print('An error ocurred. Please fix the errors and try again.')
        print('Deleting "config.py" file.')
        try:
            os.remove('config.py')
            os.remove('config.pyc')
        finally:
            raise SystemExit('Exiting now.')

from mhn import create_app, db
from flask_migrate import Migrate

# Create app instance
app = create_app()

# Initialize Flask-Migrate
migrate = Migrate(app, db)

@app.cli.command()
@click.option('--host', default='0.0.0.0', help='Host to bind to')
@click.option('--port', default=None, type=int, help='Port to bind to')
@click.option('--debug', is_flag=True, help='Enable debug mode')
def run(host, port, debug):
    """Run the development server."""
    if port is None:
        serverurl = urlparse(config.SERVER_BASE_URL)
        port = serverurl.port
    
    debug_mode = debug or config.DEBUG
    app.run(debug=debug_mode, host=host, port=port)

@app.cli.command()
def runlocal():
    """Run the development server locally."""
    serverurl = urlparse(config.SERVER_BASE_URL)
    app.run(debug=config.DEBUG, host='0.0.0.0', port=serverurl.port)

if __name__ == '__main__':
    # For backward compatibility with python manage.py
    import sys
    from urllib.parse import urlparse
    
    if len(sys.argv) > 1 and sys.argv[1] in ['run', 'runlocal']:
        if sys.argv[1] == 'run':
            # Extract parameters from command line or use defaults
            host = '0.0.0.0'
            port = None
            debug = False
            
            # Parse additional arguments
            i = 2
            while i < len(sys.argv):
                if sys.argv[i] == '--host' and i + 1 < len(sys.argv):
                    host = sys.argv[i + 1]
                    i += 2
                elif sys.argv[i] == '--port' and i + 1 < len(sys.argv):
                    port = int(sys.argv[i + 1])
                    i += 2
                elif sys.argv[i] == '--debug':
                    debug = True
                    i += 1
                else:
                    i += 1
            
            # If no port specified, get from config
            if port is None:
                serverurl = urlparse(config.SERVER_BASE_URL)
                port = serverurl.port or 5000
            
            debug_mode = debug or config.DEBUG
            print(f"Starting development server on {host}:{port}")
            app.run(debug=debug_mode, host=host, port=port)
            
        elif sys.argv[1] == 'runlocal':
            serverurl = urlparse(config.SERVER_BASE_URL)
            port = serverurl.port or 5000
            print(f"Starting local development server on 0.0.0.0:{port}")
            app.run(debug=config.DEBUG, host='0.0.0.0', port=port)
    else:
        print("Use 'flask run' or 'python manage.py run' to start the server")
        print("Use 'flask db' commands for database migrations")
