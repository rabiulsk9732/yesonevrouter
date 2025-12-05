#!/bin/bash
# Diagnose NAT packet loss issues

echo "=========================================="
echo "NAT Diagnostics"
echo "=========================================="
echo ""

echo "1. NAT Configuration:"
yesrouterctl show nat config
echo ""

echo "2. NAT Statistics:"
yesrouterctl show nat statistics
echo ""

echo "3. Active NAT Sessions (ICMP only):"
yesrouterctl show nat translations | grep -i icmp | head -20
echo ""

echo "4. Total Active Sessions:"
yesrouterctl show nat translations | wc -l
echo ""

echo "5. ARP Table:"
yesrouterctl show arp
echo ""

echo "=========================================="
echo "Analysis:"
echo "=========================================="
echo ""
echo "Key metrics to check:"
echo "  - ICMP echo requests vs replies (should be similar)"
echo "  - ICMP identifier mismatches (should be 0 or very low)"
echo "  - Out2In misses (DNAT lookup failures)"
echo "  - In2Out misses (SNAT lookup failures)"
echo ""
echo "If identifier mismatches are high:"
echo "  → Hash collisions or session timeout issues"
echo ""
echo "If Out2In misses are high:"
echo "  → DNAT lookup failing - sessions not found"
echo ""
echo "If In2Out misses are high:"
echo "  → SNAT lookup failing - session creation issues"
echo ""
