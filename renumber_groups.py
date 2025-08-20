import sqlite3

DB_NAME = 'hami_motor_coding.db'
CLASS_CODE_TO_FIX = '55'
SUPERGROUP_CODE_TO_FIX = '3' # We now use the code, which is more reliable

def renumber_groups_by_code():
    """
    Finds all groups under the supergroup with a specific code and renumbers them.
    """
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Step 1: Find the ID of the parent Class ('55')
        print(f"Searching for Class with code '{CLASS_CODE_TO_FIX}'...")
        cursor.execute("SELECT id FROM coding_structure WHERE code = ? AND layer_level = 1", (CLASS_CODE_TO_FIX,))
        parent_class = cursor.fetchone()

        if not parent_class:
            print(f"Error: Class with code '{CLASS_CODE_TO_FIX}' was not found.")
            return
        parent_class_id = parent_class['id']
        print(f"Class found with ID: {parent_class_id}")

        # Step 2: Find the ID of the Supergroup using its code and its parent's ID
        print(f"Searching for Supergroup with code '{SUPERGROUP_CODE_TO_FIX}' under this class...")
        cursor.execute("SELECT id, description FROM coding_structure WHERE code = ? AND layer_level = 2 AND parent_id = ?",
                       (SUPERGROUP_CODE_TO_FIX, parent_class_id))
        supergroup = cursor.fetchone()

        if not supergroup:
            print(f"Error: Supergroup with code '{SUPERGROUP_CODE_TO_FIX}' under Class '{CLASS_CODE_TO_FIX}' was not found.")
            return

        supergroup_id = supergroup['id']
        supergroup_name = supergroup['description']
        print(f"Supergroup '{supergroup_name}' (ID: {supergroup_id}) found successfully.")

        # Step 3: Get all children (groups) of this supergroup and renumber them
        cursor.execute("SELECT id, description, code FROM coding_structure WHERE parent_id = ? ORDER BY code", (supergroup_id,))
        groups = cursor.fetchall()

        if not groups:
            print("No groups were found under this supergroup to renumber.")
            return

        print(f"Found {len(groups)} groups to renumber. Starting the update process...")

        updated_count = 0
        for index, group in enumerate(groups):
            new_code = str(index + 1).zfill(2) # Generates 01, 02, 03, ...
            old_code = group['code']
            group_id = group['id']
            group_desc = group['description']

            if new_code != old_code:
                print(f"  - Changing code for group '{group_desc}' from '{old_code}' to '{new_code}'...")
                cursor.execute("UPDATE coding_structure SET code = ? WHERE id = ?", (new_code, group_id))
                updated_count += 1

        conn.commit()
        print(f"\nOperation complete. {updated_count} group codes were updated.")

    except sqlite3.Error as e:
        print(f"A database error occurred: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    renumber_groups_by_code()