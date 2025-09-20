#!/usr/bin/env python3
"""
ChainGuard Pro - Professional Setup Script
=========================================
Smart India Hackathon 2025 - Automated Environment Setup
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

class ChainGuardSetup:
    def __init__(self):
        self.system = platform.system()
        self.python_cmd = sys.executable
        self.venv_name = "coc_env"
        self.project_name = "ChainGuard Pro"
        
    def print_banner(self):
        print("=" * 70)
        print("🏆 CHAINGUARD PRO - SMART INDIA HACKATHON 2025")
        print("   Government Grade Evidence Management System")
        print("=" * 70)
        
    def run_command(self, cmd, description=""):
        """Execute system command with error handling"""
        print(f"⚡ {description}...")
        print(f"   Command: {cmd}")
        
        try:
            result = subprocess.run(cmd, shell=True, check=True, 
                                  capture_output=True, text=True)
            print(f"   ✅ Success")
            return True
        except subprocess.CalledProcessError as e:
            print(f"   ❌ Failed: {e}")
            print(f"   Error Output: {e.stderr}")
            return False
    
    def create_directories(self):
        """Create necessary project directories"""
        directories = [
            'core', 'modules', 'static', 'static/css', 'static/js',
            'data', 'logs', 'uploads', 'temp', 'reports', 'exports',
            'models', 'backups', 'scripts', 'tests'
        ]
        
        print("📁 Creating project directories...")
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
            print(f"   ✅ Created: {directory}")
        
        # Create __init__.py files for packages
        for package in ['core', 'modules']:
            init_file = Path(package) / "__init__.py"
            init_file.write_text(f'"""ChainGuard Pro - {package.title()} Package"""\n')
            print(f"   ✅ Created: {init_file}")
    
    def create_virtual_environment(self):
        """Create and setup virtual environment"""
        if Path(self.venv_name).exists():
            print(f"📦 Virtual environment '{self.venv_name}' already exists")
            return True
        
        print(f"📦 Creating virtual environment: {self.venv_name}")
        return self.run_command(
            f'"{self.python_cmd}" -m venv {self.venv_name}',
            "Creating virtual environment"
        )
    
    def get_pip_command(self):
        """Get pip command for current platform"""
        if self.system == "Windows":
            return f"{self.venv_name}\\Scripts\\pip"
        else:
            return f"./{self.venv_name}/bin/pip"
    
    def get_python_command(self):
        """Get python command for current platform"""
        if self.system == "Windows":
            return f"{self.venv_name}\\Scripts\\python"
        else:
            return f"./{self.venv_name}/bin/python"
    
    def install_dependencies(self):
        """Install required Python packages"""
        pip_cmd = self.get_pip_command()
        
        # Upgrade pip first
        if not self.run_command(f"{pip_cmd} install --upgrade pip", "Upgrading pip"):
            print("⚠️ Pip upgrade failed, continuing...")
        
        # Install requirements
        if Path("requirements.txt").exists():
            return self.run_command(
                f"{pip_cmd} install -r requirements.txt",
                "Installing dependencies from requirements.txt"
            )
        else:
            print("⚠️ requirements.txt not found, installing basic packages...")
            basic_packages = [
                "dash==2.14.2", "dash-bootstrap-components==1.5.0",
                "flask==2.3.3", "flask-login==0.6.3", "pymongo==4.5.0",
                "pandas==2.1.1", "numpy==1.24.3", "python-dotenv==1.0.0",
                "werkzeug==2.3.7", "pillow==10.0.1", "reportlab==4.0.4"
            ]
            
            for package in basic_packages:
                self.run_command(f"{pip_cmd} install {package}", f"Installing {package}")
            return True
    
    def create_config_files(self):
        """Create configuration files"""
        print("⚙️ Creating configuration files...")
        
        # Create .env file
        env_content = """# ChainGuard Pro Configuration
SECRET_KEY=chainguard-pro-sih-2025-secret-key
DEBUG=True
PORT=8050
HOST=0.0.0.0

# Database Configuration
MONGO_URI=mongodb+srv://fab:zfZ4o24ge9kPdpEo@coc.wdx4a64.mongodb.net/chainguard_pro?retryWrites=true&w=majority&appName=coc

# Blockchain Configuration  
GANACHE_URL=http://127.0.0.1:7545
GANACHE_NETWORK_ID=5777
CONTRACT_ADDRESS=0x260E3B39CDaF08f90E814aa01D201EEa62a5BaCe
PRIVATE_KEY=0x91014c900ec145ddef089430509ed4e1a3a583f0ef1148c6677002166e82b794

# AI Configuration
CONFIDENCE_THRESHOLD=0.85
MAX_FILE_SIZE=104857600

# Government Compliance
COMPLIANCE_MODE=BSA_2023
AUDIT_ENABLED=True
CLASSIFICATION_LEVELS=5
"""
        
        Path(".env").write_text(env_content)
        print("   ✅ Created: .env")
        
        # Create gitignore
        gitignore_content = """# ChainGuard Pro - Git Ignore
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
coc_env/
.env
*.log
data/
uploads/
temp/
reports/
exports/
.DS_Store
Thumbs.db
"""
        
        Path(".gitignore").write_text(gitignore_content)
        print("   ✅ Created: .gitignore")
    
    def verify_installation(self):
        """Verify installation by checking key components"""
        print("🔍 Verifying installation...")
        
        python_cmd = self.get_python_command()
        
        # Test imports
        test_imports = [
            "dash", "flask", "pymongo", "pandas", "numpy"
        ]
        
        for module in test_imports:
            success = self.run_command(
                f'{python_cmd} -c "import {module}; print(f\'{module} imported successfully\')"',
                f"Testing {module} import"
            )
            if not success:
                print(f"   ⚠️ Warning: {module} import failed")
        
        # Check if main files exist
        required_files = ["app.py", "config.py"]
        for file in required_files:
            if Path(file).exists():
                print(f"   ✅ Found: {file}")
            else:
                print(f"   ⚠️ Missing: {file}")
    
    def display_next_steps(self):
        """Display next steps for user"""
        print("\n" + "=" * 70)
        print("🎉 SETUP COMPLETED SUCCESSFULLY!")
        print("=" * 70)
        
        print("\n📋 NEXT STEPS:")
        print("1. Activate the virtual environment:")
        if self.system == "Windows":
            print(f"   {self.venv_name}\\Scripts\\activate")
        else:
            print(f"   source {self.venv_name}/bin/activate")
        
        print("\n2. Start the application:")
        print("   python app.py")
        print("   OR")
        print("   python run.py")
        
        print("\n3. Access the application:")
        print("   🌐 URL: http://localhost:8050")
        
        print("\n4. Login with demo accounts:")
        print("   👤 admin / admin123 (System Administrator)")
        print("   👤 analyst / password123 (Forensic Analyst)")  
        print("   👤 investigator / password123 (Senior Investigator)")
        
        print("\n💡 OPTIONAL ENHANCEMENTS:")
        print("   • Install MongoDB for full database functionality")
        print("   • Install Ganache for real blockchain features")
        print("   • Configure production environment variables")
        
        print("\n🏆 Ready for Smart India Hackathon 2025 demonstration!")
        print("=" * 70)
    
    def run_setup(self):
        """Run complete setup process"""
        self.print_banner()
        
        print("🚀 Starting ChainGuard Pro setup...")
        
        # Step 1: Create directories
        self.create_directories()
        
        # Step 2: Create virtual environment
        if not self.create_virtual_environment():
            print("❌ Failed to create virtual environment")
            sys.exit(1)
        
        # Step 3: Install dependencies
        if not self.install_dependencies():
            print("❌ Failed to install dependencies")
            sys.exit(1)
        
        # Step 4: Create config files
        self.create_config_files()
        
        # Step 5: Verify installation
        self.verify_installation()
        
        # Step 6: Display next steps
        self.display_next_steps()

def main():
    """Main setup function"""
    try:
        setup = ChainGuardSetup()
        setup.run_setup()
    except KeyboardInterrupt:
        print("\n❌ Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Setup failed with error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
