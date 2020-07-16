#include <iostream>
#include <string>
#include <iostream>     // std::cout
#include <sstream>

#include <acl/libacl.h>

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>


// /lib/x86_64-linux-gnu/libacl.so

#ifdef HAVE_ACL_GET_PERM
    #define ACL_GET_PERM acl_get_perm
#else
    #ifdef HAVE_ACL_GET_PERM_NP
        #define ACL_GET_PERM acl_get_perm_np
    #else
        // #error "An acl_get_perm-like funection is needed"
        // We don't have this constant, but we have acl_get_perm anyway
        #define ACL_GET_PERM acl_get_perm
    #endif
#endif

// not part of libadl, but of user program
struct permissions_t
{
    bool reading;
    bool writing;
    bool execution;

    // Convenience constructors
    permissions_t(char c)
    {
        reading = (c & 04);
        writing = (c & 02);
        execution = (c & 01);
    }
    permissions_t(bool rd, bool wr, bool ex)
            : reading(rd), writing(wr), execution(ex) {}
    permissions_t()
            : reading(false), writing(false), execution(false) {}
};

// not part of libadl, but of user program
struct acl_entry : permissions_t
{
    int qualifier; // Group or user
    std::string name; // Symbolic name of the qualifier
    bool valid_name;
};







void get_acl_entries_access(char* _filename)
{
    // _user_acl.clear();
    // _group_acl.clear();
    // _there_is_mask = false;
    // Get access ACL
    acl_t acl_file = acl_get_file(_filename, ACL_TYPE_ACCESS);

    // Get all the entries
    acl_entry_t acl_entry_;
    acl_permset_t permission_set;
    acl_tag_t acl_kind_tag;
    //
    int found = acl_get_entry(acl_file, ACL_FIRST_ENTRY, &acl_entry_);
    while (found == 1)
    {
        acl_get_permset(acl_entry_, &permission_set);
        acl_get_tag_type(acl_entry_, &acl_kind_tag);

        if (acl_kind_tag == ACL_USER || acl_kind_tag == ACL_GROUP)
        {
            // A user|group entry
            // Gather the permissions
            acl_entry new_acl;
            new_acl.reading = ACL_GET_PERM(permission_set, ACL_READ);
            new_acl.writing = ACL_GET_PERM(permission_set, ACL_WRITE);
            new_acl.execution = ACL_GET_PERM(permission_set, ACL_EXECUTE);
            // Get the qualifier
            if (acl_kind_tag == ACL_USER)
            {
                void* ptr_acluser = acl_get_qualifier(acl_entry_);
                uid_t* iduser = (uid_t*) ptr_acluser;
                struct passwd* p = getpwuid(*iduser);
                new_acl.valid_name = (p != NULL);
                if (p == NULL)
                {
                    std::stringstream ss;
                    ss << "(" << *iduser << ")";
                    new_acl.name = ss.str();
                }
                else
                {
                    new_acl.name = p->pw_name;
                }
                new_acl.qualifier = *iduser;
                acl_free(ptr_acluser);

                // _user_acl.push_back(new_acl);
            }
            else
            {
                void* ptr_aclgroup = acl_get_qualifier(acl_entry_);
                gid_t* idgroup = (gid_t*) ptr_aclgroup;
                struct group* g = getgrgid(*idgroup);
                new_acl.valid_name = (g != NULL);
                if (g == NULL)
                {
                    std::stringstream ss;
                    ss << "(" << *idgroup << ")";
                    new_acl.name = ss.str();
                }
                else
                {
                    new_acl.name = g->gr_name;
                }
                new_acl.qualifier = *idgroup;
                acl_free(ptr_aclgroup);

                // _group_acl.push_back(new_acl);
            }
        }
        else if (acl_kind_tag == ACL_MASK)
        {
            // The ACL mask
            // _there_is_mask = true;
            // _mask_acl.reading = ACL_GET_PERM(permission_set, ACL_READ);
            // _mask_acl.writing = ACL_GET_PERM(permission_set, ACL_WRITE);
            // _mask_acl.execution = ACL_GET_PERM(permission_set, ACL_EXECUTE);
        }
        else if (acl_kind_tag == ACL_USER_OBJ)
        {
            // Owner
            // _owner_perms.reading = ACL_GET_PERM(permission_set, ACL_READ);
            // _owner_perms.writing = ACL_GET_PERM(permission_set, ACL_WRITE);
            // _owner_perms.execution = ACL_GET_PERM(permission_set, ACL_EXECUTE);

        }
        else if (acl_kind_tag == ACL_GROUP_OBJ)
        {
            // Group
            // _group_perms.reading = ACL_GET_PERM(permission_set, ACL_READ);
            // _group_perms.writing = ACL_GET_PERM(permission_set, ACL_WRITE);
            // _group_perms.execution = ACL_GET_PERM(permission_set, ACL_EXECUTE);

        }
        else if (acl_kind_tag == ACL_OTHER)
        {
            // Other
            // _others_perms.reading = ACL_GET_PERM(permission_set, ACL_READ);
            // _others_perms.writing = ACL_GET_PERM(permission_set, ACL_WRITE);
            // _others_perms.execution = ACL_GET_PERM(permission_set, ACL_EXECUTE);
        }

        found = acl_get_entry(acl_file, ACL_NEXT_ENTRY, &acl_entry_);
    }

    acl_free(acl_file);
}





void commit_changes_to_file(char* _filename, char* _text_acl_access, char* _text_acl_default)
{
    // Get the textual representation of the ACL
    acl_t acl_access = acl_from_text(_text_acl_access);
    if (acl_access == NULL)
    {
        std::cerr << "ACL is wrong!!!" << std::endl << _text_acl_access << std::endl;

        // throw ACLManagerException(_("Textual representation of the ACL is wrong"));
    }
    if (acl_set_file(_filename, ACL_TYPE_ACCESS, acl_access) != 0)
    {
        // throw ACLManagerException(Glib::locale_to_utf8(strerror(errno)));
    }

    bool _is_directory = false;

    if (_is_directory)
    {
        // Clear the ACL
        if (acl_delete_def_file(_filename) != 0)
        {
            // throw ACLManagerException(Glib::locale_to_utf8(strerror(errno)));
        }

        // if there is something we set it, this avoids problems with FreeBSD 5.x
        if (_text_acl_default != NULL)
        {
            acl_t acl_default = acl_from_text(_text_acl_default);
            if (acl_access == NULL)
            {
                std::cerr << "Default ACL is wrong!!!" << std::endl << _text_acl_default << std::endl;
                // throw ACLManagerException(_("Default textual representation of the ACL is wrong"));
            }

            if (acl_set_file(_filename, ACL_TYPE_DEFAULT, acl_default) != 0)
            {
                // throw ACLManagerException(Glib::locale_to_utf8(strerror(errno)));
            }
        }
    }

    acl_free(acl_access);
}


int main()
{
    // Get all the entries
    acl_entry_t acl_entry_;
    acl_permset_t permission_set;
    acl_tag_t acl_kind_tag;

    const char* _filename = "/root/Desktop/CppSharp.txt";
    acl_t acl_file = acl_get_file(_filename, ACL_TYPE_ACCESS);
    int found = acl_get_entry(acl_file, ACL_FIRST_ENTRY, &acl_entry_);


    int a = acl_get_permset(acl_entry_, &permission_set);
    int b = acl_get_tag_type(acl_entry_, &acl_kind_tag);
    printf("a: %d; b: %d\n", a, b);

    acl_entry new_acl;
    new_acl.reading = ACL_GET_PERM(permission_set, ACL_READ);
    new_acl.writing = ACL_GET_PERM(permission_set, ACL_WRITE);
    new_acl.execution = ACL_GET_PERM(permission_set, ACL_EXECUTE);


    return 0;
}
