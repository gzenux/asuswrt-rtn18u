/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Certificate policy constraint processing, supporting functions,
   step initialization, preparation and wrapup procedures.
*/

#include "sshincludes.h"
#include "x509.h"
#include "cmi.h"
#include "cmi-internal.h"

#ifdef SSHDIST_CERT
#define SSH_DEBUG_MODULE "SshCMiPolicyTree"


/* Valid policy tree. */
typedef struct SshCMPolicyTreeRec  SshCMPolicyTreeStruct;

/* One level at the policy tree. */
typedef struct SshCMPolicyTreeLevelRec *SshCMPolicyTreeLevel;
typedef struct SshCMPolicyTreeLevelRec  SshCMPolicyTreeLevelStruct;

/* One node at the policy tree. */
typedef struct SshCMPolicyTreeNodeRec *SshCMPolicyTreeNode;
typedef struct SshCMPolicyTreeNodeRec  SshCMPolicyTreeNodeStruct;

/* Content of the node at the tree, the actual payload, that is. */
typedef struct SshCMPolicyNodeDataRec *SshCMPolicyNodeData;
typedef struct SshCMPolicyNodeDataRec  SshCMPolicyNodeDataStruct;

struct SshCMPolicyNodeDataRec
{
  /* Valid policy at this level */
  char *valid_policy;

  /* Set of policy qualifiers associated with the valid policy, pointer
     to external certicificate extensions. */
  SshX509ExtPolicyQualifierInfo qualifier_set;

  /* True, if certificate policies was marked as critical */
  Boolean criticality_indicator;

  /* Array of expected policy identifier OID's */
  size_t expected_policy_set_size;
  char **expected_policy_set;
};

/* Valid policy tree is actually an array. Tree contains array of
   levels, where the index of array indicates the depth of the
   tree. Each level contains array of nodes at that level. Each node
   identifies its parent, itself, and contains actual payload.

   Motivation for the approach; it is trivial to implement and
   efficient enough for the certificate path validation purposes. */
struct SshCMPolicyTreeRec
{
  /* Increasing tree node identifier. */
  SshUInt16 id;

  /* Depth of the tree and each level. */
  SshUInt16 num_levels;
  SshCMPolicyTreeLevel levels;

  /* Total number of nodes on the tree */
  SshUInt16 num_nodes;
};

struct SshCMPolicyTreeLevelRec
{
  /* Number of nodes at the level, and the nodes. */
  SshUInt16 num_nodes;
  SshCMPolicyTreeNode nodes;
};

struct SshCMPolicyTreeNodeRec
{
  /* Bookkeeping, me and my parent (at level-1) */
  SshUInt16 id;
  SshUInt16 level;
  SshUInt16 parent;

  /* Payload */
  SshCMPolicyNodeDataStruct data;
};


/* Adds new policy tree node to 'level'. Assigns parent as its parent
   node at 'level-1'. Fails if parent > 0 and level-1 does not have
   node in this index. */
static SshCMPolicyTreeNode
addnode(SshCMPolicyTree tree, SshUInt16 level, SshCMPolicyTreeNode parent)
{
  if (level < tree->num_levels)
    {
      SshCMPolicyTreeNode node, nodes;

    add_node:
      if (level > 0 && parent)
        {
          int i;
          SshCMPolicyTreeNode p;
          Boolean found = FALSE;

          for (i = 0, p = &tree->levels[level - 1].nodes[i];
               i < tree->levels[level - 1].num_nodes;
               i++, p = &tree->levels[level - 1].nodes[i])
            {
              if (p->id == parent->id)
                found = TRUE;
            }
          if (!found) return NULL;
        }

      if ((nodes =
           ssh_realloc(tree->levels[level].nodes,
                       tree->levels[level].num_nodes * sizeof(*nodes),
                       (tree->levels[level].num_nodes + 1) * sizeof(*nodes)))
          == NULL)
        return NULL;

      tree->num_nodes++;

      tree->levels[level].nodes = nodes;
      tree->levels[level].num_nodes += 1;

      node = &tree->levels[level].nodes[tree->levels[level].num_nodes - 1];
      memset(node, '\000', sizeof(*node));
      node->parent = parent ? parent->id: 0;
      node->level = level;

      tree->id += 1;
      node->id = (100 * level) + tree->id;
      return node;
    }
  else if (level == tree->num_levels)
    {
      SshCMPolicyTreeLevel levels;

      if ((levels =
           ssh_realloc(tree->levels,
                       tree->num_levels * sizeof(*levels),
                       (tree->num_levels + 1) * sizeof(*levels)))
          == NULL)
        return NULL;
      levels[level].num_nodes = 0;
      levels[level].nodes = NULL;

      tree->levels = levels;
      tree->num_levels += 1;
      goto add_node;
    }
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("PolicyTree; levels can't be sparse."));
      return NULL;
    }
}

static SshCMPolicyTreeNode
getnode(SshCMPolicyTree tree, SshUInt16 id)
{
  SshUInt16 level, i;

  level = id / 100;
  for (i = 0; i < tree->levels[level].num_nodes; i++)
    {
      if (tree->levels[level].nodes[i].id == id)
        return &tree->levels[level].nodes[i];
    }
  return NULL;
}

/* Return parent node of given node */
static SshCMPolicyTreeNode
getparent(SshCMPolicyTree tree, SshCMPolicyTreeNode node)
{
  int i;
  SshCMPolicyTreeNode p;

  for (i = 0, p = &tree->levels[node->level - 1].nodes[i];
       i < tree->levels[node->level - 1].num_nodes;
       i++, p = &tree->levels[node->level - 1].nodes[i])
    if (p->id == node->parent)
      return p;

  return NULL;
}

/* Delete node from the tree. User has to take care of deleting nodes
   children prior to deleting the node. */
static void
delnode(SshCMPolicyTree tree, SshCMPolicyTreeNode node)
{
  int i, n;
  SshCMPolicyTreeNode p;
  void *tmp;

  for (i = 0, p = &tree->levels[node->level].nodes[i];
       i < tree->levels[node->level].num_nodes;
       i++, p = &tree->levels[node->level].nodes[i])
    {
      if (p->id == node->id)
        {
          n = node->level;
          ssh_free(node->data.expected_policy_set);

          if (--tree->levels[n].num_nodes == 0)
            {
              ssh_free(tree->levels[n].nodes);
              tree->levels[n].nodes = NULL;
              tree->num_nodes--;
              return;
            }
          memmove(&p[0],
                  &p[1],
                  (tree->levels[n].num_nodes - i) * sizeof(*p));
          tmp = ssh_realloc(tree->levels[n].nodes,
                            (tree->levels[n].num_nodes + 1) * sizeof(*p),
                            (tree->levels[n].num_nodes) * sizeof(*p));
          tree->levels[n].nodes = tmp;
          tree->num_nodes--;
          return;
        }
    }
}

/* Get direct child nodes of given node. Return number of nodes, and
   fill the result into children. User has to free the returned
   children array with single ssh_free() call. */
static int
getchildren(SshCMPolicyTree tree, SshCMPolicyTreeNode node,
            SshCMPolicyTreeNode **children)
{
  int children_count = 0;
  *children = NULL;

  if (node->level < tree->num_levels - 1)
    {
      SshCMPolicyTreeLevel level = &tree->levels[node->level + 1];
      SshCMPolicyTreeNode *c;
      int i;

      if ((c = ssh_malloc(level->num_nodes * sizeof(*c))) == NULL)
        {
          return -1;
        }

      for (i = 0; i < level->num_nodes; i++)
        {
          SshCMPolicyTreeNode p = &level->nodes[i];

          if (p->parent == node->id)
            {
              c[children_count] = p;
              ++children_count;
            }
        }

      if (children_count == 0)
        {
          ssh_free(c);
        }
      else
        {
          *children = c;
        }
    }

  return children_count;
}

/* Delete nodes whose ancestor is given top node */
static void
delsubtree(SshCMPolicyTree tree, SshCMPolicyTreeNode top)
{
  int i;
  int nchildren;
  SshCMPolicyTreeNode *children;

  nchildren = getchildren(tree, top, &children);

  for (i = 0; i < nchildren; i++)
    {
      delsubtree(tree, children[i]);
    }

  if (children != NULL)
    {
      ssh_free(children);
    }

  delnode(tree, top);
}

/* Prunes one level at the policy tree, e.g. removes those nodes that
   do not have children from the tree. */
static Boolean prunelevel(SshCMPolicyTree tree, SshUInt16 level)
{
  int i;
  SshCMPolicyTreeNode p;

  for (i = 0, p = &tree->levels[level].nodes[i];
       i < tree->levels[level].num_nodes;
       p = &tree->levels[level].nodes[i])
    {
      SshCMPolicyTreeNode *children;
      int nchildren;

      nchildren = getchildren(tree, p, &children);

      if (children != NULL)
        {
          ssh_free(children);
        }

      if (nchildren < 0)
        {
          return FALSE;
        }
      else
      if (nchildren == 0)
        {
          delnode(tree, p); /* redo same index */
        }
      else
        {
          i++; /* step forward */
        }
    }

  return TRUE;
}

/* Prunes policy tree starting from given level. Those nodes that have
   no children at startlevel, then performs the same on all the levels
   above the starting level. */
static Boolean
prunetree(SshCMPolicyTree tree, SshUInt16 startlevel)
{
  if (tree->num_levels > 1)
    {
      SshInt16 i, ll = 0;

      for (i = startlevel; i != -1; i--)
        {
          if (!prunelevel(tree, i))
            return FALSE;
        }
      for (i = tree->num_levels - 1; i != -1; i--)
        {
          if (tree->levels[i].num_nodes != 0)
            ll += 1;
        }
      tree->num_levels = ll;
    }
  return TRUE;
}

/* Allocates policy constraint tree */
static SshCMPolicyTree createtree(void)
{
  SshCMPolicyTree tree;

  if ((tree = ssh_malloc(sizeof(*tree))) == NULL)
    return NULL;

  tree->num_levels = 0;
  tree->levels = NULL;
  tree->id = 1;
  tree->num_nodes = 0;
  return tree;
}

/* Frees policy constraint tree. */
static void destroytree(SshCMPolicyTree tree)
{
  int i, j;
  SshCMPolicyTreeNode node;

  for (i = 0; i < tree->num_levels; i++)
    {
      for (j = 0; j < tree->levels[i].num_nodes; j++)
        {
          node = &tree->levels[i].nodes[j];
          if (node->data.expected_policy_set_size)
            ssh_free(node->data.expected_policy_set);
        }
      ssh_free(tree->levels[i].nodes);
    }
  ssh_free(tree->levels);
  ssh_free(tree);
}

/* Print policy tree */
static void printtree(SshCMPolicyTree tree)
{
#ifdef DEBUG_LIGHT
  int i, j;
  for (i = 0; i < tree->num_levels; i++)
    {
      SshCMPolicyTreeLevel level = &tree->levels[i];

      printf("%d:\n", i);
      for (j = 0; j < level->num_nodes; j++)
        {
          printf(" %d(%d)", level->nodes[j].id, level->nodes[j].parent);
        }
      printf("\n");
    }
#endif /* DEBUG_LIGHT */
}

#define FORLEVEL(t,l,i,n)                                             \
    for ((i) = 0;                                                     \
         (l) < (t)->num_levels &&                                     \
         (i) < (t)->levels[(l)].num_nodes &&                          \
         (((n) = &(t)->levels[(l)].nodes[(i)]), 1);                   \
         ++(i))

#define FOREXPECTED(n,i,o)                                      \
    for ((i) = 0;                                               \
         (i) < (n)->data.expected_policy_set_size &&            \
         (((o) = (n)->data.expected_policy_set[i]), 1);         \
         ++(i))

static Boolean
in_expected(SshCMPolicyTreeNode node, const char *oid)
{
  int i;
  for (i = 0; i < node->data.expected_policy_set_size; i++)
    {
      if (strcmp(node->data.expected_policy_set[i], oid) == 0)
        return TRUE;
    }
  return FALSE;
}

static Boolean
add_expected(SshCMPolicyTreeNode node, char *oid)
{
  void *tmp;
  Boolean added = FALSE;

  if (!in_expected(node, oid))
    {
      tmp =
        ssh_realloc(node->data.expected_policy_set,
                    (0+node->data.expected_policy_set_size) * sizeof(char *),
                    (1+node->data.expected_policy_set_size) * sizeof(char *));
      if (tmp)
        {
          node->data.expected_policy_set = tmp;
          node->data.expected_policy_set[node->data.expected_policy_set_size] =
            oid;
          node->data.expected_policy_set_size += 1;
          added = TRUE;
        }
    }
  return added;
}

/* From expected policy set, remove oid and add non-oids from
   mappings */
static Boolean
perform_mapping(SshCMPolicyTreeNode node,
                SshX509ExtPolicyMappings mappings, const char *oid)
{
  SshX509ExtPolicyMappings p;
  Boolean mapped = FALSE;

  p = mappings;
  while (p)
    {
      if (strcmp(p->issuer_dp_oid, oid) == 0)
        {
          if (1 || in_expected(node, oid))
            {
              int i;
              for (i = 0;
                   i < node->data.expected_policy_set_size;
                   i++)
                {
                  if (strcmp(node->data.expected_policy_set[i], oid) == 0)
                    {
                      node->data.expected_policy_set[i] = p->subject_dp_oid;
                      mapped = TRUE;
                    }
                }
              if (!mapped)
                {
                  mapped = add_expected(node, p->subject_dp_oid);
                }
            }
        }
      p = p->next;
    }
  return mapped;
}

static Boolean
in_user(char **initial_policy_set, size_t initial_policy_set_size,
        char *valid)
{
  int i;
  for (i = 0; i < initial_policy_set_size; i++)
    {
      if (strcmp(initial_policy_set[i], valid) == 0)
        return TRUE;
    }
  return FALSE;
}

Boolean
ssh_cm_policy_init(SshCMCertificate cmcert,
                   SshCMPolicyTree *ptree,
                   int depth, int level,
                   SshUInt32 *policy_mapping,
                   SshUInt32 *inhibit_policy_mapping,
                   SshUInt32 *inhibit_any_policy,
                   SshUInt32 *explicit_policy)
{
  SshX509Certificate c;
  SshX509ExtPolicyInfo pinfo, p;
  Boolean pinfo_critical;
  int i, j;
  SshCMPolicyTree tree = *ptree;
  SshCMPolicyTreeNode node, anynode, child_node;
  Boolean matched;
  char *oid;

  c = cmcert->cert;
  if (tree)
    {
      /* 6.1.3.d starts here */
      if (ssh_x509_cert_get_policy_info(c, &pinfo, &pinfo_critical))
        {
          for (p = pinfo; p; p = p->next)
            {
              if (strcmp(p->oid, SSH_X509_POLICY_ANY_POLICY) == 0)
                continue;

              /* d.1 */
              anynode = NULL;
              matched = FALSE;

              FORLEVEL(tree, level - 1, i, node)
                {
                  if (strcmp(node->data.valid_policy,
                             SSH_X509_POLICY_ANY_POLICY) == 0)
                    anynode = node;

                  if (in_expected(node, p->oid))
                    {
                      /* d.1.i */
                    add_any:
                      child_node = addnode(tree, (SshUInt16)level, node);
                      /* These point within a certificate, and are
                         certificate remains valid during validation. */
                      child_node->data.valid_policy = p->oid;
                      child_node->data.qualifier_set = p->pq_list;
                      add_expected(child_node, p->oid);

                      matched = TRUE;
                      break;
                    }
                }

              if (!matched)
                {
                  if (anynode)
                    {
                      /* d.1.ii */
                      node = anynode;
                      anynode = NULL; /* Prevent entering here second time */
                      goto add_any;
                    }
                }
            }

          for (p = pinfo; p; p = p->next)
            {
              if (strcmp(p->oid, SSH_X509_POLICY_ANY_POLICY) != 0)
                continue;

              /* d.2 (a, b) */
              if (*inhibit_any_policy == 0 &&
                  !(level < depth && cmcert->self_issued))
                continue;

              FORLEVEL(tree, level - 1, i, node)
                {
                  FOREXPECTED(node, j, oid)
                    {
                      int c;
                      int nchildren;
                      SshCMPolicyTreeNode *children;
                      Boolean inchildren = FALSE;

                      nchildren = getchildren(tree, node, &children);

                      for (c = 0; c < nchildren; c++)
                        {
                          if (strcmp(children[c]->data.valid_policy, oid) == 0)
                            {
                              inchildren = TRUE;
                              break;
                            }
                        }

                      if (children != NULL)
                        {
                          ssh_free(children);
                        }

                      if (inchildren)
                        {
                          continue;
                        }

                      if (nchildren < 0)
                        {
                          continue;
                        }

                      child_node = addnode(tree, (SshUInt16)(level), node);
                      child_node->data.valid_policy = oid;
                      child_node->data.qualifier_set =
                        node->data.qualifier_set;
                      add_expected(child_node, oid);
                    }
                }
            }

          /* d.3 */
          if (!prunetree(tree, (SshUInt16)(level-1)))
            return FALSE;

          /* d.4 */
          FORLEVEL(tree, level, i, node)
            {
              node->data.criticality_indicator = pinfo_critical;
            }
        }
      else
        {
          ssh_cm_ptree_free(tree);
          *ptree = tree = NULL;
        }
    }

  if (*explicit_policy > 0 || tree != NULL)
    return TRUE;
  else
    return FALSE;
}

Boolean
ssh_cm_policy_prepare(SshCMCertificate cmcert,
                      SshCMPolicyTree *ptree,
                      int depth, int level,
                      SshUInt32 *policy_mapping,
                      SshUInt32 *inhibit_policy_mapping,
                      SshUInt32 *inhibit_any_policy,
                      SshUInt32 *explicit_policy)
{
  SshX509Certificate c;
  SshX509ExtPolicyMappings pmap, mappings;
  SshX509ExtPolicyConstraints constraints;
  Boolean mappings_critical, constraints_critical;
  SshCMPolicyTree tree = *ptree;
  SshCMPolicyTreeNode node, anynode, child_node;
  Boolean matchfound;
  int i;
  SshUInt32 ncerts;

  if (tree == NULL)
    return TRUE;

  c = cmcert->cert;

  if (ssh_x509_cert_get_policy_mappings(c, &mappings, &mappings_critical))
    {
      for (pmap = mappings; pmap; pmap = pmap->next)
        {
          /* 6.1.4.a */
          if (pmap->issuer_dp_oid == NULL ||
              strcmp(pmap->issuer_dp_oid, SSH_X509_POLICY_ANY_POLICY) == 0 ||
              strcmp(pmap->subject_dp_oid, SSH_X509_POLICY_ANY_POLICY) == 0)
            return FALSE;

          /* 6.1.4.b */
          if (pmap->issuer_dp_oid)
            {
              /* 6.1.4.b.1 */
              if (*policy_mapping > 0)
                {
                  anynode = NULL; matchfound = FALSE;
                  FORLEVEL(tree, level, i, node)
                    {
                      if (strcmp(node->data.valid_policy,
                                 pmap->issuer_dp_oid) == 0)
                        {
                          matchfound =
                            perform_mapping(node, mappings,
                                            pmap->issuer_dp_oid);
                        }
                      /* 6.1.4.b.1 */
                      if (strcmp(node->data.valid_policy,
                                 SSH_X509_POLICY_ANY_POLICY) == 0)
                        anynode = getparent(tree, node);
                    }

                  if (!matchfound && anynode)
                    {
                      child_node = addnode(tree, (SshUInt16)level, anynode);
                      child_node->data.valid_policy = pmap->issuer_dp_oid;






                      add_expected(child_node, pmap->subject_dp_oid);
                      child_node->data.criticality_indicator = FALSE;
                      child_node->data.qualifier_set = NULL;
                    }
                }

              /* 6.1.4.b.2 */
              if (*policy_mapping == 0)
                {
                  FORLEVEL(tree, level, i, node)
                    {
                      if (strcmp(node->data.valid_policy, pmap->issuer_dp_oid)
                          == 0)
                        {
                          delnode(tree, node);
                        }
                      if (!prunetree(tree, (SshUInt16)(level-1)))
                        return FALSE;
                    }
                }
            }
        }
    }
  /* 6.1.4.g */

  /* 6.1.4.h */
  if (!cmcert->self_issued)
    {
      if (*explicit_policy)
        *explicit_policy -= 1;
      if (*policy_mapping)
        *policy_mapping -= 1;
      if (*inhibit_any_policy)
        *inhibit_any_policy -= 1;
    }

  /* 6.1.4.i */
  if (ssh_x509_cert_get_policy_constraints(c,
                                           &constraints,
                                           &constraints_critical))
    {
      if (constraints->require != -1 &&
          constraints->require < *explicit_policy)
        *explicit_policy = constraints->require;
      if (constraints->inhibit != -1 &&
          constraints->inhibit < *policy_mapping)
        *policy_mapping = constraints->inhibit;
    }

  /* 6.1.4.j */
  {
    Boolean critical;
    if (ssh_x509_cert_get_inhibit_any_policy(c, &ncerts, &critical))
      {
        if (ncerts < *inhibit_any_policy)
          *inhibit_any_policy = ncerts;
      }
  }
  return TRUE;
}

static void
intersect_policy(SshCMPolicyTree tree,
                 int level,
                 char **initial_policy_set, size_t initial_policy_set_size)
{
  SshCMPolicyTreeNode node, child_node, parent = NULL;
  int i, ii, n, u, v, l;
  int level_1;
  SshUInt16 *valid_policy_node_set;

  /* iii.1 */

  if (tree->num_levels == 0)
    return;

  if ((valid_policy_node_set = ssh_calloc(tree->num_nodes, sizeof(int)))
      == NULL)
    return;

  n = 0;
  for (l = 1; l < tree->num_levels; l++)
    {
      FORLEVEL(tree, l, i, node)
        {
          parent = getparent(tree, node);
          if (strcmp(parent->data.valid_policy, SSH_X509_POLICY_ANY_POLICY)
              == 0)
            {
              valid_policy_node_set[n++] = node->id;
            }
        }
    }

  /* iii.2 */
  for (i = 0; i < n; i++)
    {
      if ((node = getnode(tree, valid_policy_node_set[i])) == NULL)
        continue;

      if (strcmp(node->data.valid_policy, SSH_X509_POLICY_ANY_POLICY) == 0 ||
          in_user(initial_policy_set,
                  initial_policy_set_size,
                  node->data.valid_policy))
        continue;

      delsubtree(tree, node);
    }

  /* iii.3 */
  FORLEVEL(tree, level, i, node)
    {
      if (strcmp(node->data.valid_policy, SSH_X509_POLICY_ANY_POLICY) == 0 &&
          (initial_policy_set_size > 1 ||
           (initial_policy_set_size == 1 &&
            strcmp(initial_policy_set[0], SSH_X509_POLICY_ANY_POLICY) != 0)))
        {
          Boolean in_initial = FALSE;
          SshCMPolicyTreeNode tmp;

          /* b */
          for (u = 0; u < initial_policy_set_size; u++)
            {
              for (v = 0; v < u; v++)
                {
                  tmp = getnode(tree, valid_policy_node_set[v]);
                  if (tmp &&
                      strcmp(initial_policy_set[u],
                             tmp->data.valid_policy) == 0)
                    {
                      /* this initial policy in valid_policy_set */
                      in_initial = TRUE;
                      break;
                    }
                }

              if (in_initial)
                continue;

              if (level > 0)
                {
                  level_1 = level - 1;
                  FORLEVEL(tree, level_1, ii, parent)
                    {
                      if (strcmp(parent->data.valid_policy,
                                 SSH_X509_POLICY_ANY_POLICY) == 0)
                        break;
                    }
                  if (parent)
                    {
                      SshX509ExtPolicyQualifierInfo qinfo;
                      Boolean cind;

                      qinfo = node->data.qualifier_set;
                      cind = node->data.criticality_indicator;

                      delnode(tree, node);

                      child_node = addnode(tree, (SshUInt16)level, parent);
                      child_node->data.valid_policy = initial_policy_set[u];
                      add_expected(child_node, initial_policy_set[u]);
                      child_node->data.criticality_indicator = cind;
                      child_node->data.qualifier_set = qinfo;
                    }
                }
            }
        }
    }

  /* iii.4 */
  if (level > 0)
    prunetree(tree, (SshUInt16)(level-1));

  ssh_free(valid_policy_node_set);
}

Boolean
ssh_cm_policy_wrapup(SshCMCertificate cmcert,
                     SshCMPolicyTree *ptree,
                     int depth, int level,
                     char **initial_policy_set, size_t initial_policy_set_size,
                     SshUInt32 *policy_mapping,
                     SshUInt32 *inhibit_policy_mapping,
                     SshUInt32 *inhibit_any_policy,
                     SshUInt32 *explicit_policy)
{
  SshX509Certificate c;
  SshCMPolicyTree tree = *ptree;
  SshX509ExtPolicyConstraints constraints;
  Boolean constraints_critical;

  c = cmcert->cert;
  if (!cmcert->self_signed)
    {
      if (*explicit_policy > 0)
        *explicit_policy -= 1;
    }

  /* 6.1.5.b */
  if (ssh_x509_cert_get_policy_constraints(c,
                                           &constraints,
                                           &constraints_critical))
    {
      if (constraints->require == 0)
        *explicit_policy = 0;
    }

  /* 6.1.5.g */
  if (tree)
    {
      if (initial_policy_set_size == 0  ||
          (initial_policy_set_size == 1 &&
           strcmp(initial_policy_set[0], SSH_X509_POLICY_ANY_POLICY) == 0))
        {
          ;
        }
      else
        {
          intersect_policy(tree,
                           level,
                           initial_policy_set, initial_policy_set_size);
        }
    }

  if (*explicit_policy > 0 ||
      (tree && tree->num_levels > 1))
    return TRUE;

  return FALSE;
}

SshCMPolicyTree ssh_cm_ptree_alloc(void)
{
  SshCMPolicyTree tree = createtree();

  if (tree)
    {
      SshCMPolicyTreeNode initial;

      if ((initial = addnode(tree, 0, NULL)) != NULL)
        {
          initial->data.valid_policy = SSH_X509_POLICY_ANY_POLICY;
          initial->data.qualifier_set = NULL;
          initial->data.criticality_indicator = FALSE;
          if (!add_expected(initial, SSH_X509_POLICY_ANY_POLICY))
            {
              destroytree(tree);
              return NULL;
            }
        }
      else
        {
          destroytree(tree);
          return NULL;
        }
    }
  return tree;

}

void ssh_cm_ptree_free(SshCMPolicyTree tree)
{
  if (tree && tree->num_levels == 0) printtree(tree);
  if (tree)
    destroytree(tree);
}
#endif /* SSHDIST_CERT */
