#!/bin/bash
# Quick check of NAT statistics after test

echo "=========================================="
echo "NAT Statistics After Test"
echo "=========================================="
echo ""

yesrouterctl show nat statistics | grep -A 20 "Lookup\|ICMP"

echo ""
echo "Active Sessions:"
yesrouterctl show nat translations | wc -l
