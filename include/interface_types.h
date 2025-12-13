/**
 * @file interface_types.h
 * @brief Interface type definitions
 */

#ifndef INTERFACE_TYPES_H
#define INTERFACE_TYPES_H

/* Interface types */
enum interface_type {
    IF_TYPE_PHYSICAL = 0,
    IF_TYPE_VLAN,
    IF_TYPE_LAG,
    IF_TYPE_LOOPBACK,
    IF_TYPE_DUMMY,
    IF_TYPE_UNKNOWN
};

#endif /* INTERFACE_TYPES_H */
