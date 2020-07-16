#include <stdlib.h>
#include <stdio.h>
#include <sys/acl.h>
#include <sys/types.h>

// from qnx:
// http://www.qnx.com/developers/docs/qnxcar2/index.jsp?topic=%2Fcom.qnx.doc.neutrino.prog%2Ftopic%2Facl_example.html
int Test()
{
    acl_t my_acl;
    char  *text_acl;
    ssize_t len;
    acl_entry_t my_entry;
    gid_t  group_id;
    acl_permset_t permset;

    system ("touch my_file.txt");

    // Get the file's ACL.
    my_acl = acl_get_file ("my_file.txt", ACL_TYPE_ACCESS);
    if (my_acl == NULL)
    {
        perror ("acl_get_file()");
        return EXIT_FAILURE;
    }


    // Convert the ACL into text so we can see what it is.
    text_acl = acl_to_text (my_acl, &len);
    if (text_acl == NULL)
    {
        perror ("acl_to_text()");
        return EXIT_FAILURE;
    }
    printf ("Initial ACL: %s\n", text_acl);

    // We're done with the text version, so release it.
    if (acl_free (text_acl) == -1)
    {
        perror ("acl_free()");
        return EXIT_FAILURE;
    }

    // Add an entry for a named group to the ACL.
    if (acl_create_entry (&my_acl, &my_entry) == -1)
    {
        perror ("acl_create_entry()");
        return EXIT_FAILURE;
    }

    if (acl_set_tag_type (my_entry, ACL_USER) == -1)
    {
        perror ("acl_set_tag_type");
        return EXIT_FAILURE;
    }

    group_id = 120;
    if (acl_set_qualifier (my_entry, &group_id) == -1)
    {
        perror ("acl_set_qualifier");
        return EXIT_FAILURE;
    }

    // Modify the permissions.
    if (acl_get_permset (my_entry, &permset) == -1)
    {
        perror ("acl_get_permset");
        return EXIT_FAILURE;
    }

    if (acl_clear_perms (permset ) == -1)
    {
        perror ("acl_clear_perms");
        return EXIT_FAILURE;
    }

    if (acl_add_perm (permset, ACL_READ))
    {
        perror ("acl_add_perm");
        return EXIT_FAILURE;
    }

    // Recalculate the mask entry.
    // TODO: &fix correct ?
    if (acl_calc_mask (&my_acl))
    {
        perror ("acl_calc_mask");
        return EXIT_FAILURE;
    }

    /// Make sure the ACL is valid.
    if (acl_valid (my_acl) ==-1)
    {
        perror ("acl_valid");
        return EXIT_FAILURE;
    }

    // Update the ACL for the file.
    if (acl_set_file ("my_file.txt", ACL_TYPE_ACCESS, my_acl) == -1)
    {
        perror ("acl_set_file");
        return EXIT_FAILURE;
    }

    // Free the ACL in working storage.
    if (acl_free (my_acl) == -1)
    {
        perror ("acl_free()");
        return EXIT_FAILURE;
    }

    // Verify that it all worked, by getting and printing the file's ACL.
    my_acl = acl_get_file ("my_file.txt", ACL_TYPE_ACCESS);
    if (my_acl == NULL)
    {
        perror ("acl_get_file()");
        return EXIT_FAILURE;
    }

    text_acl = acl_to_text (my_acl, &len);
    if (text_acl == NULL)
    {
        perror ("acl_to_text()");
        return EXIT_FAILURE;
    }
    printf ("Updated ACL: %s\n", text_acl);

    // We're done with the text version, so release it.
    if (acl_free (text_acl) == -1)
    {
        perror ("acl_free()");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
