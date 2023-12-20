const submitButton = document.querySelector('.js-submit-form');
const timeOut = 1500;

/**
* Add Loading Animation
*/
const addLoading = button => {
  const addLoader = document.createElement("div");

  addLoader.classList.add("btn-loader");
  button.appendChild(addLoader);
  button.classList.add("is-loading");
  button.setAttribute("disabled", "disabled");

  // Demo Remove Loader
  setTimeout(() => {
    removeLoading(button);
  }, timeOut);
};

/**
* Remove Loading Animation
*/
const removeLoading = button => {
  const loader = button.querySelector(".btn-loader");

  if (loader) {
    button.classList.remove("is-loading");
    loader.remove();
    button.removeAttribute("disabled");
  }
};

/**
* Demo
*/
submitButton.addEventListener('click', e => {
  const button = e.currentTarget;

  removeLoading(button);
  addLoading(button);
});