#!/usr/bin/env python3
"""
RedStorm Cleanup Service
Automatically removes old data files and logs
"""
import os
import shutil
import time
import logging
from datetime import datetime, timedelta
from pathlib import Path
import asyncio
from typing import List, Tuple
import schedule

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CleanupService:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.data_dir = self.base_dir / "data"
        self.logs_dir = self.base_dir / "logs"
        self.backend_logs_dir = self.base_dir / "backend" / "logs"
        
        # Configuration
        self.data_retention_hours = 3  # Keep data for 3 hours
        self.log_retention_hours = 1   # Keep logs for 1 hour
        
        logger.info(f"Cleanup service initialized")
        logger.info(f"Data directory: {self.data_dir}")
        logger.info(f"Logs directory: {self.logs_dir}")
    
    def get_file_age(self, file_path: Path) -> float:
        """Get file age in hours"""
        try:
            if not file_path.exists():
                return 0
            
            # Get file modification time
            file_mtime = file_path.stat().st_mtime
            current_time = time.time()
            age_hours = (current_time - file_mtime) / 3600
            return age_hours
        except Exception as e:
            logger.error(f"Error getting file age for {file_path}: {e}")
            return 0
    
    def is_file_old(self, file_path: Path, max_age_hours: int) -> bool:
        """Check if file is older than specified hours"""
        age_hours = self.get_file_age(file_path)
        return age_hours > max_age_hours
    
    def safe_remove(self, path: Path) -> bool:
        """Safely remove file or directory"""
        try:
            if path.is_file():
                path.unlink()
                logger.info(f"Removed file: {path}")
                return True
            elif path.is_dir():
                shutil.rmtree(path)
                logger.info(f"Removed directory: {path}")
                return True
        except PermissionError:
            logger.warning(f"Permission denied: {path}")
        except Exception as e:
            logger.error(f"Error removing {path}: {e}")
        return False
    
    def cleanup_data_folder(self):
        """Remove data files older than 3 hours"""
        logger.info("Starting data cleanup...")
        
        if not self.data_dir.exists():
            logger.warning(f"Data directory does not exist: {self.data_dir}")
            return
        
        removed_count = 0
        total_size_freed = 0
        
        # Walk through data directory
        for root, dirs, files in os.walk(self.data_dir):
            root_path = Path(root)
            
            # Check files
            for file in files:
                file_path = root_path / file
                if self.is_file_old(file_path, self.data_retention_hours):
                    file_size = file_path.stat().st_size if file_path.exists() else 0
                    if self.safe_remove(file_path):
                        removed_count += 1
                        total_size_freed += file_size
            
            # Check directories (only empty ones)
            for dir_name in dirs[:]:  # Create a copy to modify during iteration
                dir_path = root_path / dir_name
                try:
                    if (self.is_file_old(dir_path, self.data_retention_hours) and 
                        not any(dir_path.iterdir())):  # Check if directory is empty
                        if self.safe_remove(dir_path):
                            dirs.remove(dir_name)  # Remove from list to prevent further traversal
                            removed_count += 1
                except Exception as e:
                    logger.error(f"Error checking directory {dir_path}: {e}")
        
        logger.info(f"Data cleanup completed. Removed {removed_count} items, freed {total_size_freed / (1024*1024):.2f} MB")
    
    def cleanup_logs_folder(self):
        """Remove log files older than 1 hour"""
        logger.info("Starting logs cleanup...")
        
        removed_count = 0
        total_size_freed = 0
        
        # Define log directories to clean
        log_directories = [self.logs_dir, self.backend_logs_dir]
        
        for logs_dir in log_directories:
            if not logs_dir.exists():
                logger.warning(f"Logs directory does not exist: {logs_dir}")
                continue
            
            # Common log file extensions
            log_extensions = {'.log', '.txt', '.out', '.err', '.debug'}
            
            # Walk through logs directory
            for root, dirs, files in os.walk(logs_dir):
                root_path = Path(root)
                
                # Check files
                for file in files:
                    file_path = root_path / file
                    file_ext = file_path.suffix.lower()
                    
                    # Only process log files
                    if file_ext in log_extensions or 'log' in file.lower():
                        if self.is_file_old(file_path, self.log_retention_hours):
                            file_size = file_path.stat().st_size if file_path.exists() else 0
                            if self.safe_remove(file_path):
                                removed_count += 1
                                total_size_freed += file_size
        
        logger.info(f"Logs cleanup completed. Removed {removed_count} log files, freed {total_size_freed / (1024*1024):.2f} MB")
    
    def get_cleanup_stats(self) -> dict:
        """Get statistics about what would be cleaned up"""
        stats = {
            'data_files': [],
            'log_files': [],
            'total_data_size': 0,
            'total_log_size': 0
        }
        
        # Check data files
        if self.data_dir.exists():
            for root, dirs, files in os.walk(self.data_dir):
                root_path = Path(root)
                for file in files:
                    file_path = root_path / file
                    if self.is_file_old(file_path, self.data_retention_hours):
                        try:
                            size = file_path.stat().st_size
                            stats['data_files'].append({
                                'path': str(file_path.relative_to(self.base_dir)),
                                'size': size,
                                'age_hours': self.get_file_age(file_path)
                            })
                            stats['total_data_size'] += size
                        except Exception as e:
                            logger.error(f"Error getting stats for {file_path}: {e}")
        
        # Check log files
        log_directories = [self.logs_dir, self.backend_logs_dir]
        for logs_dir in log_directories:
            if logs_dir.exists():
                for root, dirs, files in os.walk(logs_dir):
                    root_path = Path(root)
                    for file in files:
                        file_path = root_path / file
                        file_ext = file_path.suffix.lower()
                        
                        if file_ext in {'.log', '.txt', '.out', '.err', '.debug'} or 'log' in file.lower():
                            if self.is_file_old(file_path, self.log_retention_hours):
                                try:
                                    size = file_path.stat().st_size
                                    stats['log_files'].append({
                                        'path': str(file_path.relative_to(self.base_dir)),
                                        'size': size,
                                        'age_hours': self.get_file_age(file_path)
                                    })
                                    stats['total_log_size'] += size
                                except Exception as e:
                                    logger.error(f"Error getting stats for {file_path}: {e}")
        
        return stats
    
    def print_cleanup_preview(self):
        """Show what would be cleaned up without actually doing it"""
        logger.info("=== CLEANUP PREVIEW ===")
        stats = self.get_cleanup_stats()
        
        if stats['data_files']:
            logger.info(f"Data files to be removed ({len(stats['data_files'])} files, {stats['total_data_size'] / (1024*1024):.2f} MB):")
            for file_info in stats['data_files'][:10]:  # Show first 10
                logger.info(f"  - {file_info['path']} ({file_info['size'] / 1024:.1f} KB, {file_info['age_hours']:.1f} hours old)")
            if len(stats['data_files']) > 10:
                logger.info(f"  ... and {len(stats['data_files']) - 10} more files")
        else:
            logger.info("No data files to remove")
        
        if stats['log_files']:
            logger.info(f"Log files to be removed ({len(stats['log_files'])} files, {stats['total_log_size'] / (1024*1024):.2f} MB):")
            for file_info in stats['log_files'][:10]:  # Show first 10
                logger.info(f"  - {file_info['path']} ({file_info['size'] / 1024:.1f} KB, {file_info['age_hours']:.1f} hours old)")
            if len(stats['log_files']) > 10:
                logger.info(f"  ... and {len(stats['log_files']) - 10} more files")
        else:
            logger.info("No log files to remove")
        
        logger.info("=== END PREVIEW ===")
    
    def run_cleanup(self, preview_only: bool = False):
        """Run the complete cleanup process"""
        logger.info("="*50)
        logger.info("Starting cleanup process...")
        
        if preview_only:
            self.print_cleanup_preview()
        else:
            self.cleanup_data_folder()
            self.cleanup_logs_folder()
        
        logger.info("Cleanup process completed")
        logger.info("="*50)
    
    def start_scheduler(self):
        """Start the scheduled cleanup service"""
        logger.info("Starting cleanup scheduler...")
        
        # Schedule data cleanup every 30 minutes
        schedule.every(30).minutes.do(self.cleanup_data_folder)
        
        # Schedule logs cleanup every 15 minutes (since we want 1 hour retention)
        schedule.every(15).minutes.do(self.cleanup_logs_folder)
        
        # Schedule full cleanup with stats every hour
        schedule.every().hour.do(lambda: self.run_cleanup(preview_only=False))
        
        logger.info("Scheduler started:")
        logger.info(f"  - Data cleanup: Every 30 minutes (retention: {self.data_retention_hours} hours)")
        logger.info(f"  - Logs cleanup: Every 15 minutes (retention: {self.log_retention_hours} hours)")
        logger.info("  - Full cleanup with stats: Every hour")
        
        try:
            while True:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
        except KeyboardInterrupt:
            logger.info("Cleanup scheduler stopped")

# Standalone cleanup function
def run_cleanup_once(preview: bool = False):
    """Run cleanup once and exit"""
    service = CleanupService()
    service.run_cleanup(preview_only=preview)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="RedStorm Cleanup Service")
    parser.add_argument("--preview", action="store_true", help="Show what would be cleaned up without actually doing it")
    parser.add_argument("--once", action="store_true", help="Run cleanup once and exit")
    parser.add_argument("--schedule", action="store_true", help="Start scheduled cleanup service")
    parser.add_argument("--data-hours", type=int, default=3, help="Data retention hours (default: 3)")
    parser.add_argument("--log-hours", type=int, default=1, help="Log retention hours (default: 1)")
    
    args = parser.parse_args()
    
    service = CleanupService()
    service.data_retention_hours = args.data_hours
    service.log_retention_hours = args.log_hours
    
    if args.schedule:
        service.start_scheduler()
    elif args.once or args.preview:
        run_cleanup_once(preview=args.preview)
    else:
        print("Use --preview to see what would be cleaned up, --once to run once, or --schedule to start scheduler")
        print("Use --help for more options")