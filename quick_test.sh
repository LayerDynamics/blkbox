#!/bin/bash

# Quick test of BlkBox honeypot endpoints

echo "🧪 Quick BlkBox Test"
echo "===================="
echo ""

# Test HTTP honeypot
echo "Testing HTTP honeypot..."
curl -v http://localhost:8080/ 2>&1 | head -20
echo ""

echo "Testing WordPress admin..."
curl -s http://localhost:8080/wp-admin/ | head -10
echo ""

echo "Testing phpMyAdmin..."
curl -s http://localhost:8080/phpmyadmin/ | head -10
echo ""

echo "Testing .git exposure..."
curl -s http://localhost:8080/.git/config | head -10
echo ""

# Test management API
echo "Checking attacks via API..."
curl -s http://localhost:9000/api/attacks | jq '.' 2>/dev/null || curl -s http://localhost:9000/api/attacks
echo ""

echo "Done! Check dashboard at http://localhost:9000/dashboard"
