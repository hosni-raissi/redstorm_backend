#!/usr/bin/env python3
"""
Simple cleanup runner for RedStorm
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from cleanup_service import run_cleanup_once

if __name__ == "__main__":
    print("RedStorm Cleanup Service")
    print("="*30)
    
    # Preview mode - show what would be cleaned up
    print("PREVIEW MODE - Showing what would be cleaned up:")
    run_cleanup_once(preview=True)
    
    print("\nRun cleanup? (y/N): ", end="")
    response = input().strip().lower()
    
    if response == 'y':
        print("\nRunning cleanup...")
        run_cleanup_once(preview=False)
        print("Cleanup completed!")
    else:
        print("Cleanup cancelled.")