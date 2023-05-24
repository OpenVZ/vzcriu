#include "util.h"
#include "common/xmalloc.h"
#include "covering-mounts.h"

struct covering_mount *get_covering_mount(struct covering_mounts *cms, char *root)
{
       struct covering_mount *cm;

       list_for_each_entry(cm, &cms->list, siblings) {
               if (is_sub_path(root, cm->mnt->root))
                       return cm;
       }

       return NULL;
}

bool cms_fully_covered(struct covering_mounts *cms, char *root)
{
	struct covering_mount *cm;

	list_for_each_entry(cm, &cms->list, siblings) {
		if (!is_sub_path(cm->mnt->root, root))
			return false;
	}

	return true;
}

void pop_covered_mounts(struct covering_mounts *cms, char *root, struct list_head *covered)
{
       struct covering_mount *cm, *t;

       list_for_each_entry_safe(cm, t, &cms->list, siblings) {
               if (is_sub_path(cm->mnt->root, root)) {
                       list_move(&cm->siblings, covered);
                       cms->count--;
               }
       }
}

int update_covering_mounts(struct covering_mounts *cms, struct mount_info *mi)
{
       struct covering_mount *cm;

       cm = get_covering_mount(cms, mi->root);
       if (!cm) {
               LIST_HEAD(covered);

               pop_covered_mounts(cms, mi->root, &covered);
               while (!list_empty(&covered)) {
                       struct covering_mount *tcm;

                       tcm = list_first_entry(&covered, struct covering_mount, siblings);
                       list_del(&tcm->siblings);
                       xfree(tcm);
               }

               cm = xzalloc(sizeof(struct covering_mount));
               if (!cm)
                       return -1;

               cm->mnt = mi;
               list_add(&cm->siblings, &cms->list);
               cms->count++;
       }

       return 0;
}
