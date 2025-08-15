#!/bin/bash

# SQL Injection Training Lab - Automated Installer
# This script sets up the complete training environment

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}"
    echo "=================================================="
    echo "🔓 SQL Injection Training Lab Installer"
    echo "=================================================="
    echo -e "${NC}"
}

# Main installation function
main() {
    print_header
    
    print_status "Starting SQL Injection Lab setup..."
    
    # Check if we're in a codespace
    if [ ! -z "$CODESPACES" ]; then
        print_success "Running in GitHub Codespaces environment"
    else
        print_warning "Not detected as Codespaces - continuing anyway"
    fi
    
    # Update system packages
    print_status "Updating system packages..."
    sudo apt-get update -qq
    sudo apt-get install -y sqlite3 curl tree > /dev/null 2>&1
    print_success "System packages updated"
    
    # Check Python version
    print_status "Checking Python installation..."
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version)
        print_success "Found $PYTHON_VERSION"
    else
        print_error "Python3 not found!"
        exit 1
    fi
    
    # Create project directory structure
    print_status "Creating project directory structure..."
    mkdir -p /workspace/sql-injection-lab
    cd /workspace/sql-injection-lab
    mkdir -p data .devcontainer
    print_success "Directory structure created"
    
    # Create requirements.txt
    print_status "Creating requirements.txt..."
    cat > requirements.txt << 'EOF'
Flask==2.3.3
Werkzeug==2.3.7
Jinja2==3.1.2
EOF
    print_success "Requirements file created"
    
    # Install Python dependencies
    print_status "Installing Python dependencies..."
    pip3 install --no-cache-dir -r requirements.txt > /dev/null 2>&1
    print_success "Python dependencies installed"
    
    # Create database initialization script
    print_status "Creating database initialization script..."
    cat > init_db.py << 'EOF'
import sqlite3
import os

DATABASE = '/workspace/sql-injection-lab/data/vulnerable_app.db'

def init_database():
    # Ensure the data directory exists
    os.makedirs(os.path.dirname(DATABASE), exist_ok=True)
    
    # Create database and tables
    conn = sqlite3.connect(DATABASE)
    
    # Create users table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')
    
    # Create a secrets table (for advanced challenges)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            secret_name TEXT NOT NULL,
            secret_value TEXT NOT NULL,
            classification TEXT DEFAULT 'confidential'
        )
    ''')
    
    # Insert sample users (passwords stored in plain text for demo purposes)
    users_data = [
        ('admin', 'admin123', 'admin@company.com', 'administrator'),
        ('john', 'password', 'john@company.com', 'user'),
        ('jane', 'qwerty', 'jane@company.com', 'user'),
        ('bob', '123456', 'bob@company.com', 'user'),
        ('alice', 'alice2023', 'alice@company.com', 'manager'),
        ('test', 'test', 'test@company.com', 'user')
    ]
    
    # Insert sample secrets
    secrets_data = [
        ('Database Password', 'super_secret_db_password_2023', 'top_secret'),
        ('API Key', 'api_key_12345_abcdef', 'confidential'),
        ('Admin Token', 'admin_token_xyz789', 'restricted'),
        ('Encryption Key', 'enc_key_aes256_secure', 'top_secret'),
        ('Backup Location', '/secure/backups/company_data', 'internal')
    ]
    
    try:
        # Insert users if they don't exist
        for user_data in users_data:
            conn.execute('''
                INSERT OR IGNORE INTO users (username, password, email, role) 
                VALUES (?, ?, ?, ?)
            ''', user_data)
        
        # Insert secrets if they don't exist
        for secret_data in secrets_data:
            conn.execute('''
                INSERT OR IGNORE INTO secrets (secret_name, secret_value, classification) 
                VALUES (?, ?, ?)
            ''', secret_data)
        
        conn.commit()
        print("✅ Database initialized successfully!")
        print("📊 Sample data inserted:")
        print("   - 6 user accounts")
        print("   - 5 secret records")
        
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
    
    finally:
        conn.close()

if __name__ == '__main__':
    init_database()
EOF
    print_success "Database initialization script created"
    
    # Initialize the database
    print_status "Initializing SQLite database with sample data..."
    python3 init_db.py
    print_success "Database initialized with sample data"
    
    # Create the main Flask application
    print_status "Creating main Flask application..."
    cat > app.py << 'EOF'
from flask import Flask, render_template_string, request, redirect, url_for, flash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'vulnerable_key_for_demo'

DATABASE = '/workspace/sql-injection-lab/data/vulnerable_app.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Home page with login form
@app.route('/')
def home():
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>SQL Injection Lab - Vulnerable Login</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; background: #f0f2f5; }
        .container { background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        input, button { padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 5px; width: 100%; box-sizing: border-box; }
        button { background: #007bff; color: white; cursor: pointer; font-weight: bold; }
        button:hover { background: #0056b3; }
        .alert { padding: 15px; margin: 10px 0; border-radius: 5px; }
        .alert-danger { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
        .alert-success { background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
        .hint { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 15px 0; }
        pre { background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; border: 1px solid #e9ecef; }
        .challenge { background: #e7f3ff; padding: 20px; border-radius: 8px; margin: 15px 0; border-left: 4px solid #007bff; }
        details { margin: 10px 0; }
        summary { cursor: pointer; font-weight: bold; padding: 5px; }
        .nav-links { display: flex; gap: 10px; flex-wrap: wrap; }
        .nav-links a { background: #6c757d; color: white; padding: 10px 15px; text-decoration: none; border-radius: 5px; font-size: 14px; }
        .nav-links a:hover { background: #5a6268; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔓 SQL Injection Training Lab</h1>
        <p><strong>⚠️ Educational Environment Only</strong> - This application contains intentional vulnerabilities</p>
    </div>
    
    <div class="container">
        <h2>Vulnerable Login System</h2>
        <form method="POST" action="/login">
            <div>
                <label><strong>Username:</strong></label>
                <input type="text" name="username" placeholder="Enter username" required>
            </div>
            <div>
                <label><strong>Password:</strong></label>
                <input type="password" name="password" placeholder="Enter password" required>
            </div>
            <button type="submit">🔑 Login</button>
        </form>
    </div>

    <div class="challenge">
        <h3>🎯 Challenge 1: Authentication Bypass</h3>
        <p>Try to bypass the login without knowing valid credentials.</p>
        <details>
            <summary>💡 Hint (click to expand)</summary>
            <div class="hint">
                <p>The SQL query being executed is:</p>
                <pre>SELECT * FROM users WHERE username = '{username}' AND password = '{password}'</pre>
                <p><strong>Try these techniques:</strong></p>
                <ul>
                    <li>SQL comments: <code>admin'--</code></li>
                    <li>Always true conditions: <code>' OR '1'='1'--</code></li>
                    <li>Boolean logic: <code>' OR 1=1--</code></li>
                </ul>
            </div>
        </details>
    </div>

    <div class="challenge">
        <h3>🎯 Challenge 2: Data Extraction</h3>
        <p>Once you've bypassed authentication, try to extract information about the database structure.</p>
        <details>
            <summary>💡 Hint (click to expand)</summary>
            <div class="hint">
                <p>Use UNION SELECT to extract data from system tables:</p>
                <pre>' UNION SELECT sql,name,type,1,2 FROM sqlite_master--</pre>
                <p>Look for hidden tables like <code>secrets</code>!</p>
            </div>
        </details>
    </div>

    <div class="container">
        <h3>📚 Learning Resources</h3>
        <div class="nav-links">
            <a href="/users">👥 View Users</a>
            <a href="/safe-login">🔒 Safe Implementation</a>
            <a href="/payloads">🎯 Attack Payloads</a>
            <a href="/database">💾 Database Schema</a>
        </div>
    </div>

    {% with messages = get_flashed_messages() %}
        {% if messages %}
            {% for message in messages %}
                <div class="alert alert-danger">{{ message }}</div>
            {% endfor %}
        {% endif %}
    {% endwith %}
</body>
</html>
    ''')

# Vulnerable login endpoint
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # VULNERABLE SQL QUERY - DON'T USE THIS IN PRODUCTION!
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    
    try:
        conn = get_db_connection()
        print(f"🔍 Executing query: {query}")
        
        result = conn.execute(query).fetchone()
        conn.close()
        
        if result:
            return render_template_string('''
            <html>
            <head>
                <title>Login Success!</title>
                <style>
                    body { font-family: Arial; max-width: 800px; margin: 50px auto; padding: 20px; background: #f0f2f5; }
                    .container { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                    .success { background: #d4edda; padding: 20px; border-radius: 8px; border-left: 4px solid #28a745; }
                    .query-info { background: #fff3cd; padding: 15px; border-radius: 5px; border-left: 4px solid #ffc107; }
                    pre { background: #f8f9fa; padding: 10px; border-radius: 5px; overflow-x: auto; }
                    .btn { display: inline-block; background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin: 10px 5px 0 0; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>🎉 Login Successful!</h1>
                    <div class="success">
                        <h3>User Information:</h3>
                        <p><strong>ID:</strong> {{ result[0] }}</p>
                        <p><strong>Username:</strong> {{ result[1] }}</p>
                        <p><strong>Email:</strong> {{ result[3] }}</p>
                        <p><strong>Role:</strong> {{ result[4] }}</p>
                    </div>
                    <div class="query-info">
                        <h4>🔍 SQL Query Executed:</h4>
                        <pre>{{ query }}</pre>
                    </div>
                    <a href="/" class="btn">🏠 Back to Home</a>
                    <a href="/users" class="btn">👥 View All Users</a>
                </div>
            </body>
            </html>
            ''', result=result, query=query)
        else:
            flash('❌ Invalid credentials!')
            return redirect(url_for('home'))
    
    except Exception as e:
        return render_template_string('''
        <html>
        <head><title>SQL Error</title>
        <style>
            body { font-family: Arial; max-width: 800px; margin: 50px auto; padding: 20px; background: #f0f2f5; }
            .container { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .error { background: #f8d7da; padding: 20px; border-radius: 8px; border-left: 4px solid #dc3545; }
        </style>
        </head>
        <body>
            <div class="container">
                <h1>💥 SQL Error</h1>
                <div class="error">
                    <h3>Error Details:</h3>
                    <pre>{{ error }}</pre>
                    <h4>🔍 Failed Query:</h4>
                    <pre>{{ query }}</pre>
                </div>
                <a href="/" style="display: inline-block; background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-top: 15px;">🏠 Back to Home</a>
            </div>
        </body>
        </html>
        ''', error=str(e), query=query)

# View users table
@app.route('/users')
def users():
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, email, role FROM users').fetchall()
    conn.close()
    
    users_html = ""
    for user in users:
        users_html += f"<tr><td>{user['id']}</td><td>{user['username']}</td><td>{user['email']}</td><td>{user['role']}</td></tr>"
    
    return render_template_string(f'''
    <html>
    <head>
        <title>Users Reference</title>
        <style>
            body {{ font-family: Arial; max-width: 900px; margin: 50px auto; padding: 20px; background: #f0f2f5; }}
            .container {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
            th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
            th {{ background-color: #007bff; color: white; }}
            tr:nth-child(even) {{ background-color: #f8f9fa; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>👥 Users Table (Reference)</h1>
            <table>
                <tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th></tr>
                {users_html}
            </table>
            <p><strong>⚠️ Note:</strong> Passwords are stored as plain text for demonstration purposes!</p>
            <a href="/" style="display: inline-block; background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">🏠 Back to Lab</a>
        </div>
    </body>
    </html>
    ''')

# Attack payloads reference
@app.route('/payloads')
def payloads():
    return render_template_string('''
    <html>
    <head>
        <title>Attack Payloads</title>
        <style>
            body { font-family: Arial; max-width: 1000px; margin: 20px auto; padding: 20px; background: #f0f2f5; }
            .container { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }
            pre { background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; border: 1px solid #e9ecef; }
            .payload-category { background: #e7f3ff; padding: 15px; border-radius: 8px; margin: 15px 0; border-left: 4px solid #007bff; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🎯 SQL Injection Payloads</h1>
            <p>Use these payloads to practice different attack techniques:</p>
        </div>
        
        <div class="payload-category">
            <h3>🔓 Authentication Bypass</h3>
            <pre>Username: admin'--
Password: anything

Username: ' OR '1'='1'--
Password: anything

Username: ' OR 1=1--
Password: anything</pre>
        </div>
        
        <div class="payload-category">
            <h3>🔍 Information Gathering</h3>
            <pre>Username: ' UNION SELECT 1,2,3,4,5--
Password: anything

Username: ' UNION SELECT sql,name,type,1,2 FROM sqlite_master--
Password: anything</pre>
        </div>
        
        <div class="payload-category">
            <h3>📊 Data Extraction</h3>
            <pre>Username: ' UNION SELECT 1,username,password,email,role FROM users--
Password: anything

Username: ' UNION SELECT 1,secret_name,secret_value,classification,2 FROM secrets--
Password: anything</pre>
        </div>
        
        <div class="container">
            <h3>⚠️ Important Notes</h3>
            <ul>
                <li>Always use <code>--</code> to comment out the rest of the original query</li>
                <li>Match the number of columns in UNION SELECT statements</li>
                <li>Use single quotes <code>'</code> for string literals in SQL</li>
                <li>SQLite uses <code>sqlite_master</code> table for metadata</li>
            </ul>
            <a href="/" style="display: inline-block; background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">🏠 Back to Lab</a>
        </div>
    </body>
    </html>
    ''')

# Database schema viewer
@app.route('/database')
def database():
    conn = get_db_connection()
    tables = conn.execute("SELECT name, sql FROM sqlite_master WHERE type='table'").fetchall()
    conn.close()
    
    tables_html = ""
    for table in tables:
        tables_html += f"<div class='table-info'><h4>{table['name']}</h4><pre>{table['sql']}</pre></div>"
    
    return render_template_string(f'''
    <html>
    <head>
        <title>Database Schema</title>
        <style>
            body {{ font-family: Arial; max-width: 1000px; margin: 20px auto; padding: 20px; background: #f0f2f5; }}
            .container {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            .table-info {{ background: #f8f9fa; padding: 15px; margin: 15px 0; border-radius: 8px; border-left: 4px solid #28a745; }}
            pre {{ background: #fff; padding: 10px; border-radius: 5px; overflow-x: auto; border: 1px solid #ddd; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>💾 Database Schema</h1>
            <p>Complete database structure for the SQL injection lab:</p>
            {tables_html}
            <a href="/" style="display: inline-block; background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-top: 20px;">🏠 Back to Lab</a>
        </div>
    </body>
    </html>
    ''')

# Safe login implementation
@app.route('/safe-login')
def safe_login():
    return render_template_string('''
    <html>
    <head>
        <title>Safe Implementation</title>
        <style>
            body { font-family: Arial; max-width: 1000px; margin: 20px auto; padding: 20px; background: #f0f2f5; }
            .container { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }
            pre { background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto; border: 1px solid #e9ecef; }
            .safe-code { background: #d4edda; padding: 20px; border-radius: 8px; border-left: 4px solid #28a745; }
            .vulnerable-code { background: #f8d7da; padding: 20px; border-radius: 8px; border-left: 4px solid #dc3545; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔒 Secure Implementation Guide</h1>
        </div>
        
        <div class="safe-code">
            <h3>✅ Secure Code (Use This)</h3>
            <pre>
def safe_login(username, password):
    conn = get_db_connection()
    # Use parameterized queries with ? placeholders
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    result = conn.execute(query, (username, password)).fetchone()
    conn.close()
    return result
            </pre>
        </div>
        
        <div class="vulnerable-code">
            <h3>❌ Vulnerable Code (Never Do This)</h3>
            <pre>
def vulnerable_login(username, password):
    # String formatting/concatenation - VULNERABLE!
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    result = conn.execute(query).fetchone()
    return result
            </pre>
        </div>
        
        <div class="container">
            <h3>🛡️ Prevention Best Practices</h3>
            <ol>
                <li><strong>Parameterized Queries:</strong> Always use prepared statements</li>
                <li><strong>Input Validation:</strong> Validate and sanitize all inputs</li>
                <li><strong>Least Privilege:</strong> Limit database user permissions</li>
                <li><strong>Error Handling:</strong> Don't expose database errors to users</li>
                <li><strong>WAF:</strong> Use Web Application Firewalls</li>
                <li><strong>Regular Testing:</strong> Perform security audits</li>
            </ol>
            <a href="/" style="display: inline-block; background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">🏠 Back to Lab</a>
        </div>
    </body>
    </html>
    ''')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
EOF
    print_success "Flask application created"
    
    # Create startup script
    print_status "Creating startup script..."
    cat > start.sh << 'EOF'
#!/bin/bash
echo "🚀 Starting SQL Injection Training Lab..."
echo "📍 Lab will be available at: http://localhost:5000"
echo "⚠️  This is for educational purposes only!"
echo ""
python3 app.py
EOF
    chmod +x start.sh
    print_success "Startup script created"
    
    # Create README
    print_status "Creating documentation..."
    cat > README.md << 'EOF'
# 🔓 SQL Injection Training Lab

A deliberately vulnerable web application for learning SQL injection techniques.

## ⚠️ Security Warning
**This application contains intentional vulnerabilities. Use only for educational purposes!**

## 🚀 Quick Start
```bash
# Start the lab
./start.sh

# Or run directly
python3 app.py
```

## 🎯 Challenges
1. **Authentication Bypass** - Login without valid credentials
2. **Data Extraction** - Extract hidden information from database
3. **Schema Discovery** - Map the database structure

## 📚 Learning Resources
- `/users` - View sample user data
- `/payloads` - Attack payload examples
- `/database` - Database schema
- `/safe-login` - Secure implementation guide

## 🛡️ Key Learning Points
- Always use parameterized queries
- Never trust user input
- Implement proper error handling
- Apply principle of least privilege

---
**Remember**: Understanding vulnerabilities helps you build more secure applications! 🔒
EOF
    print_success "Documentation created"
    
    # Set proper permissions
    print_status "Setting file permissions..."
    chmod +x start.sh
    chmod 644 *.py *.txt *.md
    print_success "Permissions set"
    
    # Display final information
    print_success "Installation completed successfully!"
    echo ""
    echo -e "${GREEN}=================================================="
    echo "🎉 SQL Injection Training Lab Ready!"
    echo "==================================================${NC}"
    echo ""
    echo -e "${BLUE}📁 Installation Directory:${NC} $(pwd)"
    echo -e "${BLUE}📊 Database Location:${NC} $(pwd)/data/vulnerable_app.db"
    echo -e "${BLUE}🌐 Web Interface:${NC} http://localhost:5000"
    echo ""
    echo -e "${YELLOW}🚀 To start the lab:${NC}"
    echo "   ./start.sh"
    echo ""
    echo -e "${YELLOW}📚 Available endpoints:${NC}"
    echo "   / - Main login form"
    echo "   /users - User reference table"
    echo "   /payloads - Attack examples"
    echo "   /database - Schema information"
    echo "   /safe-login - Secure implementation"
    echo ""
    echo -e "${RED}⚠️  Important Security Notice:${NC}"
    echo "   This lab contains intentional vulnerabilities"
    echo "   Use only in isolated environments for education"
    echo "   Never deploy to production or public networks"
    echo ""
    
    # Check if we can start the app automatically
    if [ ! -z "$CODESPACES" ]; then
        echo -e "${BLUE}🔧 Codespaces detected - starting lab automatically...${NC}"
        echo "   The lab will be available on the forwarded port 5000"
        echo "   Look for the 'Ports' tab in VS Code"
        echo ""
        # Start the app in the background for Codespaces
        nohup python3 app.py > app.log 2>&1 &
        sleep 2
        if pgrep -f "python3 app.py" > /dev/null; then
            print_success "Lab started successfully in background!"
            echo -e "${GREEN}✅ Ready to start learning SQL injection techniques!${NC}"
        else
            print_warning "Auto-start failed. Run './start.sh' manually."
        fi
    else
        echo -e "${BLUE}💡 To start learning:${NC}"
        echo "   1. Run: ./start.sh"
        echo "   2. Open: http://localhost:5000"
        echo "   3. Start with Challenge 1: Authentication Bypass"
    fi
    
    echo ""
    print_success "Happy learning! 🎓"
}

# Run the main function
main "$@"
EOF
