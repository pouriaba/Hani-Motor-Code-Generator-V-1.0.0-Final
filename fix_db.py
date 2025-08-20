import sqlite3

print("Starting database fix...")
try:
    conn = sqlite3.connect('hami_motor_coding.db')
    cursor = conn.cursor()

    # حذف تمام رکوردهای اشتباه از لایه ۷ که نامشان "شرح کالا" است
    cursor.execute("DELETE FROM coding_structure WHERE layer_level = 7 AND description = 'شرح کالا'")

    # اطمینان از اینکه هیچ کد تولید شده‌ای به این آیتم اشتباه ارجاع نمی‌دهد
    # (این بخش برای اطمینان بیشتر است)
    # توجه: این دستور ممکن است کدهای معتبری که تصادفاً عبارت "شرح کالا" را دارند هم حذف کند
    # اما با توجه به ماهیت سیستم، این احتمال کم است.
    # cursor.execute("DELETE FROM generated_products WHERE full_description LIKE '%شرح کالا%'")

    conn.commit()
    # در نسخه اصلاح شده، از f-string برای نمایش تعداد ردیف های حذف شده استفاده می کنیم
    print(f"{cursor.rowcount} incorrect record(s) with description 'شرح کالا' deleted successfully.")
    conn.close()

except Exception as e:
    print(f"An error occurred: {e}")

print("Fix script finished.")