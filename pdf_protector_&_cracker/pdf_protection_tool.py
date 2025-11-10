import PyPDF2
import sys

def create_protected_pdf(input_pdf_path, output_pdf_path, password):
    try:
        # Open the input PDF file
        with open(input_pdf_path, 'rb') as input_pdf_file:
            reader = PyPDF2.PdfReader(input_pdf_file)
            writer = PyPDF2.PdfWriter()

            # Copy all pages from the reader to the writer
            for page_num in range(len(reader.pages)):
                writer.add_page(reader.pages[page_num])

            # Set the user and owner passwords
            writer.encrypt(password)

            # Write the protected PDF to the output file
            with open(output_pdf_path, 'wb') as output_pdf_file:
                writer.write(output_pdf_file)

            print(f"Password-Protected PDF saved as {output_pdf_path}")

    except FileNotFoundError:
        print(f"Error: The file {input_pdf_path} was not found.")
    except PyPDF2.utils.PdfReadError:
        print(f"Error: The file {input_pdf_path} is not a valid PDF.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def main():
    if len(sys.argv) != 4:
        print("Usage python3 pdf_protection_tool.py <input_pdf_path> <output_pdf_path> <password>")
        sys.exit(1)

    input_pdf_path = sys.argv[1]
    output_pdf_path = sys.argv[2]
    password = sys.argv[3]

    create_protected_pdf(input_pdf_path, output_pdf_path, password)

if __name__ == "__main__":
    main()
