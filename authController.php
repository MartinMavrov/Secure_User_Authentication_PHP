<?php


require 'dbconnect/dbconnect.inc.php';
include_once 'include/functiontest_input.inc.php';
$errors= array();
$username= "";
$email ="";




if (isset($_POST['Submit'])) {


  $firstname = test_input($_POST["First_Name"]);
  $lastname = test_input($_POST["Last_Name"]);
  $email = test_input($_POST["Email"]);
  $phone = test_input($_POST["Phone_Number"]);
  $username =test_input ($_POST["Username"]);
  $password = test_input($_POST["Password"]);
  $passwordconf= test_input($_POST["ConfPassword"]);
  $street = test_input($_POST["Address"]);
  $city = test_input($_POST["City"]);
  $state = test_input($_POST["State"]);
  $zip = test_input($_POST["Zip"]);


 

  

  if($password!==$passwordconf){
    $errors['password'] =" The password(s) do not match";
  }


  
  $emailQuery = "SELECT * FROM customer_info WHERE Email=? LIMIT 1";
  $stmt = $conn->prepare($emailQuery);//prepared statement to avoid sql injection
  $stmt->bind_param("s",$email);
  $stmt->execute();
  $result = $stmt->get_result();
  $userCount = $result->num_rows;//count num rows
  if($userCount>0){
    $errors['email']="Email already exists";
  }
  if(count($errors)===0){
    $password= password_hash($password, PASSWORD_DEFAULT);//hash func.

    $query = "INSERT INTO customer_info(First_Name, Last_Name, Email, Phone_Number, Username, Password, Address, City, State, zip, Created_at) ";
    $query .= "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, FROM_UNIXTIME(UNIX_TIMESTAMP()))";

    $stmt = $conn->prepare($query);
    $stmt->bind_param("sssssssssi", $firstname, $lastname, $email, $phone, $username, $password, $street, $city, $state, $zip);
    if ($stmt->execute()) {
      header("Location:first.php");
    } else {
      $error['db_error']="Database error: failed to register";
    }
    if ($stmt->execute()) {
      $user_id = $conn->insert_id;//db connection
      
      header("Location:first.php");
      exit();
    }
  }
}
if(isset($_POST['login'])){
  $username = test_input($_POST["username"]);
  $password = test_input($_POST["password"]);
   
  

  if(empty($username)){
    $errors['username']="Required Field";
  }
  if(empty($password)){
    $errors['password']="Required Field";
  }
  //start checking errors and log in the user 
  if(count($errors)===0){
    $sql ="SELECT * FROM customer_info WHERE Email=? OR Username=? LIMIT 1";
    $stmt=$conn->prepare($sql);//prepared statement
    $stmt->bind_param("ss", $email, $username);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();//save info in association array
    $userCount = $result->num_rows;
    if($userCount===0){
      $errors['users']="user doesn't exists";
    }
    else{
    if(password_verify($password, $user['Password'])){
      
      header("Location:table.php");
      exit();
    } else{
      $errors['login_fail']="Wrong Credential";
    }
    }
    }
  }
  



//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////




?>