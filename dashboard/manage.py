#!/usr/bin/env python3
"""SIEM Africa - Django manage.py"""
import os
import sys


def main():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'siem_africa.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Django n'est pas installé. Installez-le : pip3 install django"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()
