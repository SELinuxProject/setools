/**
 *  @file
 *  Defines the public interface for searching and iterating over
 *  Xen statements.
 *
 *  @author Richard Haines richard_c_haines@btinternet.com
 *  Derived from portcon_query.h
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 */

#ifndef QPOL_XEN_QUERY_H
#define QPOL_XEN_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>
#include <qpol/iterator.h>
#include <qpol/policy.h>

	typedef struct qpol_iomemcon qpol_iomemcon_t;
	typedef struct qpol_ioportcon qpol_ioportcon_t;
	typedef struct qpol_pcidevicecon qpol_pcidevicecon_t;
	typedef struct qpol_pirqcon qpol_pirqcon_t;
	typedef struct qpol_devicetreecon qpol_devicetreecon_t;

/******************************* iomemcon **************************/
/**
 *  Get a single iomemcon statement by range.
 *  @param policy The policy from which to get the iomemcon statement.
 *  @param low The low addr of the range of addrs (or single addr).
 *  @param high The high addr of the range of addrs; if searching for a
 *  single addr, set high equal to low.
 *  @param ocon Pointer in which to store the statement returned.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *ocon will be NULL.
 */
	extern int qpol_policy_get_iomemcon_by_addr(
					    const qpol_policy_t *policy,
					    uint64_t low, uint64_t high,
					    const qpol_iomemcon_t **ocon);

/**
 *  Get an iterator for the iomemcon statements in a policy.
 *  @param policy The policy from which to create the iterator.
 *  @param iter Iterator over items of type qpol_iomemcon_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long
 *  as the policy is unmodified.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_policy_get_iomemcon_iter(const qpol_policy_t *policy,
						    qpol_iterator_t **iter);

/**
 *  Get the low addr from a iomemcon statement.
 *  @param policy the policy associated with the iomemcon statement.
 *  @param ocon The iomemcon statement from which to get the low addr.
 *  @param addr Pointer to set to the addr.
 *  @return 0 on success < 0 on failure; if the call fails,
 *  errno will be set and *addr will be 0.
 */
	extern int qpol_iomemcon_get_low_addr(const qpol_policy_t *policy,
					    const qpol_iomemcon_t *ocon,
					    uint64_t *addr);

/**
 *  Get the high addr from a iomemcon statement.
 *  @param policy the policy associated with the iomemcon statement.
 *  @param ocon The iomemcon statement from which to get the high addr.
 *  @param addr Pointer to set to the addr.
 *  @return 0 on success < 0 on failure; if the call fails,
 *  errno will be set and *addr will be 0.
 */
	extern int qpol_iomemcon_get_high_addr(const qpol_policy_t *policy,
					    const qpol_iomemcon_t *ocon,
					    uint64_t *addr);

/**
 *  Get the context from a iomemcon statement.
 *  @param policy the policy associated with the iomemcon statement.
 *  @param ocon The iomemcon statement from which to get the context.
 *  @param context Pointer in which to store the context.
 *  The caller should not free this pointer.
 *  @return 0 on success < 0 on failure; if the call fails,
 *  errno will be set and *context will be NULL.
 */
	extern int qpol_iomemcon_get_context(const qpol_policy_t *policy,
					    const qpol_iomemcon_t *ocon,
					    const qpol_context_t **context);

/******************************* ioportcon **************************/
/**
 *  Get a single ioportcon statement by range.
 *  @param policy The policy from which to get the ioportcon statement.
 *  @param low The low port of the range of ports (or single port).
 *  @param high The high port of the range of ports; if searching for a
 *  single port, set high equal to low.
 *  @param ocon Pointer in which to store the statement returned.
 *  The caller should not free this pointer.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *ocon will be NULL.
 */
	extern int qpol_policy_get_ioportcon_by_port(
					    const qpol_policy_t *policy,
					    uint32_t low, uint32_t high,
					    const qpol_ioportcon_t **ocon);

/**
 *  Get an iterator for the ioportcon statements in a policy.
 *  @param policy The policy from which to create the iterator.
 *  @param iter Iterator over items of type qpol_ioportcon_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long
 *  as the policy is unmodified.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_policy_get_ioportcon_iter(const qpol_policy_t *policy,
						    qpol_iterator_t **iter);

/**
 *  Get the low port from a ioportcon statement.
 *  @param policy the policy associated with the ioportcon statement.
 *  @param ocon The ioportcon statement from which to get the low port.
 *  @param port Pointer to set to the port.
 *  @return 0 on success < 0 on failure; if the call fails,
 *  errno will be set and *port will be 0.
 */
	extern int qpol_ioportcon_get_low_port(const qpol_policy_t *policy,
					    const qpol_ioportcon_t *ocon,
					    uint32_t *port);

/**
 *  Get the high port from a ioportcon statement.
 *  @param policy the policy associated with the ioportcon statement.
 *  @param ocon The ioportcon statement from which to get the high port.
 *  @param port Pointer to set to the port.
 *  @return 0 on success < 0 on failure; if the call fails,
 *  errno will be set and *port will be 0.32
 */
	extern int qpol_ioportcon_get_high_port(const qpol_policy_t *policy,
					    const qpol_ioportcon_t *ocon,
					    uint32_t *port);

/**
 *  Get the context from a ioportcon statement.
 *  @param policy the policy associated with the ioportcon statement.
 *  @param ocon The ioportcon statement from which to get the context.
 *  @param context Pointer in which to store the context.
 *  The caller should not free this pointer.
 *  @return 0 on success < 0 on failure; if the call fails,
 *  errno will be set and *context will be NULL.
 */
	extern int qpol_ioportcon_get_context(const qpol_policy_t *policy,
					    const qpol_ioportcon_t *ocon,
					    const qpol_context_t **context);



/******************************* pcidevicecon **************************/
/**
 *  Get an iterator for the pcidevicecon statements in a policy.
 *  @param policy The policy from which to create the iterator.
 *  @param iter Iterator over items of type qpol_pcidevicecon_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long
 *  as the policy is unmodified.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_policy_get_pcidevicecon_iter(
					    const qpol_policy_t *policy,
					    qpol_iterator_t **iter);

/**
 *  Get the device id from a pcidevicecon statement.
 *  @param policy the policy associated with the pcidevicecon statement.
 *  @param ocon The pcidevicecon statement from which to get the low addr.
 *  @param device Pointer to set to the device.
 *  @return 0 on success < 0 on failure; if the call fails,
 *  errno will be set and *device will be 0.
 */
	extern int qpol_pcidevicecon_get_device(const qpol_policy_t *policy,
					    const qpol_pcidevicecon_t *ocon,
					    uint32_t *device);


/**
 *  Get the context from a pcidevicecon statement.
 *  @param policy the policy associated with the pcidevicecon statement.
 *  @param ocon The pcidevicecon statement from which to get the context.
 *  @param context Pointer in which to store the context.
 *  The caller should not free this pointer.
 *  @return 0 on success < 0 on failure; if the call fails,
 *  errno will be set and *context will be NULL.
 */
	extern int qpol_pcidevicecon_get_context(const qpol_policy_t *policy,
					    const qpol_pcidevicecon_t *ocon,
					    const qpol_context_t **context);

/************************* pirqcon *******************************/

/**
 *  Get an iterator for the pirqcon statements in a policy.
 *  @param policy The policy from which to create the iterator.
 *  @param iter Iterator over items of type qpol_pirqcon_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long
 *  as the policy is unmodified.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_policy_get_pirqcon_iter(const qpol_policy_t *policy,
						    qpol_iterator_t **iter);

/**
 *  Get the irq id from a pirqcon statement.
 *  @param policy the policy associated with the pirqcon statement.
 *  @param ocon The pirqcon statement from which to get the irq.
 *  @param irq Pointer to set to the irq.
 *  @return 0 on success < 0 on failure; if the call fails,
 *  errno will be set and *irq will be 0.
 */
	extern int qpol_pirqcon_get_irq(const qpol_policy_t *policy,
					    const qpol_pirqcon_t *ocon,
					    uint16_t *irq);


/**
 *  Get the context from a pirqcon statement.
 *  @param policy the policy associated with the pirqcon statement.
 *  @param ocon The pirqcon statement from which to get the context.
 *  @param context Pointer in which to store the context.
 *  The caller should not free this pointer.
 *  @return 0 on success < 0 on failure; if the call fails,
 *  errno will be set and *context will be NULL.
 */
	extern int qpol_pirqcon_get_context(const qpol_policy_t *policy,
					    const qpol_pirqcon_t *ocon,
					    const qpol_context_t **context);

/************************* devicetreecon *******************************/

/**
 *  Get an iterator for the devicetreecon statements in a policy.
 *  @param policy The policy from which to create the iterator.
 *  @param iter Iterator over items of type qpol_devicetreecon returned.
 *  The caller is responsible for calling qpol_iterator_destroy
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long
 *  as the policy is unmodified.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_policy_get_devicetreecon_iter(
					    const qpol_policy_t *policy,
					    qpol_iterator_t **iter);

/**
 *  Get the path from a devicetreecon statement.
 *  @param policy the policy associated with the devicetreecon statement.
 *  @param ocon The devicetreecon statement from which to get the path.
 *  @param path Pointer to set to the path.
 *  @return 0 on success < 0 on failure; if the call fails,
 *  errno will be set and *path will be 0.
 */
	extern int qpol_devicetreecon_get_path(const qpol_policy_t *policy,
					    const qpol_devicetreecon_t *ocon,
					    char **path);


/**
 *  Get the context from a devicetreecon statement.
 *  @param policy the policy associated with the devicetreecon statement.
 *  @param ocon The devicetreecon statement from which to get the context.
 *  @param context Pointer in which to store the context.
 *  The caller should not free this pointer.
 *  @return 0 on success < 0 on failure; if the call fails,
 *  errno will be set and *context will be NULL.
 */
	extern int qpol_devicetreecon_get_context(const qpol_policy_t *policy,
					    const qpol_devicetreecon_t *ocon,
					    const qpol_context_t **context);
#ifdef	__cplusplus
}
#endif

#endif				       /* QPOL_XEN_QUERY_H */
