/**
 *  @file
 *  Defines the public interface for searching and iterating over default objects.
 *
 *  @author Richard Haines richard_c_haines@btinternet.com
 *
 *  Copyright (C) 2006-2009 Tresys Technology, LLC
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
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef QPOL_DEFAULT_OBJECT_QUERY_H
#define QPOL_DEFAULT_OBJECT_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>
#include <qpol/iterator.h>
#include <qpol/policy.h>


	typedef struct qpol_default_object qpol_default_object_t;

/**
 *  Get an iterator for the default_object types in a policy.
 *  @param policy The policy from which to create the iterator.
 *  @param iter Iterator over items of type qpol_isid_t returned.
 *  The caller is responsible for calling qpol_iterator_destroy 
 *  to free memory used by this iterator.
 *  It is important to note that this iterator is only valid as long 
 *  as the policy is unmodified.
 *  @return 0 on success and < 0 on failure; if the call fails, 
 *  errno will be set and *iter will be NULL.
 */
	extern int qpol_policy_get_default_object_iter(const qpol_policy_t *policy, qpol_iterator_t **iter);

/**
 *  Get the name which identifies a default_object class from its datum.
 *  @param policy The policy with which class is associated.
 *  @param datum default_object datum for which to get the name. Must be non-NULL.
 *  @param name Pointer to the string in which to store the name.
 *  Must be non-NULL. The caller should not free the string.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *name will be NULL.
 */
	extern int qpol_default_object_get_class(const qpol_policy_t *policy, const qpol_default_object_t *datum, const char **name);

/**
 *  Get the value of a default user source/dest from its datum.
 *  @param policy The policy with which the default object is associated.
 *  @param datum default_object datum for which to get the value. Must be non-NULL.
 *  @param default Pointer to the value in which to store the default.
 *  Must be non-NULL. The caller should not free the string.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *default will be 0.
 */
	extern int qpol_default_object_get_user_default(const qpol_policy_t *policy, const qpol_default_object_t *datum, const char **value);

/**
 *  Get the value of a default role source/dest from its datum.
 *  @param policy The policy with which the default object type is associated.
 *  @param datum default_object datum for which to get the value. Must be non-NULL.
 *  @param default Pointer to the value in which to store the default.
 *  Must be non-NULL. The caller should not free the string.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *default will be 0.
 */
	extern int qpol_default_object_get_role_default(const qpol_policy_t *policy, const qpol_default_object_t *datum, const char **value);

/**
 *  Get the value of a default type source/dest from its datum.
 *  @param policy The policy with which the default object type is associated.
 *  @param datum default_object datum for which to get the value. Must be non-NULL.
 *  @param default Pointer to the value in which to store the default.
 *  Must be non-NULL. The caller should not free the string.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *default will be 0.
 */
	extern int qpol_default_object_get_type_default(const qpol_policy_t *policy, const qpol_default_object_t *datum, const char **value);

/**
 *  Get the value of a default range source/dest from its datum.
 *  @param policy The policy with which the default object type is associated.
 *  @param datum default_object datum for which to get the value. Must be non-NULL.
 *  @param default Pointer to the value in which to store the default.
 *  Must be non-NULL. The caller should not free the string.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and *default will be 0.
 */
	extern int qpol_default_object_get_range_default(const qpol_policy_t *policy, const qpol_default_object_t *datum, const char **value);


#ifdef	__cplusplus
}
#endif

#endif				       
