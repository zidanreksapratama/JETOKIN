$(document).ready(function() {
  // Fungsi untuk mengelola menu toggle dan smooth scroll
  $('#menu').click(function() {
      $(this).toggleClass('fa-times');
      $('.navbar').toggleClass('nav-toggle');
  });

  $(window).on('scroll load', function() {
      $('#menu').removeClass('fa-times');
      $('.navbar').removeClass('nav-toggle');

      if ($(window).scrollTop() > 0) {
          $('.scroll-top').show();
      } else {
          $('.scroll-top').hide();
      }

      // Scroll spy untuk navbar
      $('section').each(function() {
          let height = $(this).height();
          let offset = $(this).offset().top - 200;
          let id = $(this).attr('id');
          let top = $(window).scrollTop();

          if (top > offset && top < offset + height) {
              $('.navbar ul li a').removeClass('active');
              $('.navbar').find(`[href="#${id}"]`).addClass('active');
          }
      });
  });

  // Smooth scrolling
  $('a[href*="#"]').on('click', function(e) {
      e.preventDefault();
      $('html, body').animate({
          scrollTop: $($(this).attr('href')).offset().top,
      }, 500, 'linear');
  });

  // Inisialisasi untuk video stream dan canvas
  let video;
  let canvas;
  let nameInput;

  let streaming = false;  // Pastikan variabel streaming dideklarasikan di awal

  function init() {
      video = document.getElementById("videoElement");
      canvas = document.getElementById("canvas");
      nameInput = document.getElementById("name");

      navigator.mediaDevices.getUserMedia({ video: true })
          .then(stream => {
              video.srcObject = stream;
          })
          .catch(error => {
              console.log("Error accessing webcam:", error);
              alert("Cannot access webcam");
          });
  }

  // Fungsi untuk menangkap foto dari video
  function capture() {
      const context = canvas.getContext("2d");
      context.drawImage(video, 0, 0, canvas.width, canvas.height);
      canvas.style.display = "block";
      video.style.display = "none";
  }

  // Fungsi untuk melakukan registrasi pengguna dengan foto
  function register() {
      const name = nameInput.value;
      const photo = dataURItoBlob(canvas.toDataURL());

      if (!name || !photo) {
          alert("Please enter your name and capture a photo.");
          return;
      }

      const formData = new FormData();
      formData.append("name", name);
      formData.append("photo", photo, `${name}.jpg`);

      fetch("/register_face_id", {
          method: "POST",
          body: formData
      })
      .then(response => response.json())
      .then(data => {
          if (data.success) {
              alert("Registration successful!");
              window.location.href = "/login_face_id";
          } else {
              alert("Registration failed, please try again.");
          }
      })
      .catch(error => {
          console.log("Error:", error);
      });
  }

  // Fungsi untuk melakukan login dengan foto yang diambil
  function login() {  
      const context = canvas.getContext("2d");
      context.drawImage(video, 0, 0, canvas.width, canvas.height);
      const photo = dataURItoBlob(canvas.toDataURL());

      if (!photo) {
          alert("Please capture a photo.");
          return;
      }

      const formData = new FormData();
      formData.append("photo", photo, "login.jpg");

      fetch("/login_face_id", {
          method: "POST",
          body: formData
      })
      .then(response => response.json())
      .then(data => {
          if (data.success) {
              alert("Login successful!");
              window.location.href = "/success?user_name=" + data.user_name;
          } else {
              alert("Login failed: Face not recognized.");
          }
      })
      .catch(error => {
          console.log("Error:", error);
      });
  }

  // Fungsi untuk mengonversi Data URI menjadi Blob
  function dataURItoBlob(dataURI) {
      const byteString = atob(dataURI.split(",")[1]);
      const mimeString = dataURI.split(",")[0].split(":")[1].split(";")[0];

      const ab = new ArrayBuffer(byteString.length);
      const ia = new Uint8Array(ab);
      for (let i = 0; i < byteString.length; i++) {
          ia[i] = byteString.charCodeAt(i);
      }
      return new Blob([ab], { type: mimeString });
  }

  // Inisialisasi kamera dan video streaming saat halaman dimuat
  init();

  // Event listener untuk tombol capture, register, dan login
  document.getElementById('capture-button').addEventListener('click', capture);
  document.getElementById('register-button').addEventListener('click', register);
  document.getElementById('login-button').addEventListener('click', login);
});


