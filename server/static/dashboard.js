const timeFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
const countryNames = new Intl.DisplayNames(undefined, { type: 'region' });

document.querySelectorAll('time[datetime]').forEach((element) => {
    element.textContent = timeFormat.format(new Date(element.dateTime));
});

document.querySelectorAll('form[data-confirm]').forEach((form) => {
    form.addEventListener('submit', (event) => {
        if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
});

document.querySelectorAll('[data-country]').forEach((element) => {
    element.textContent = countryNames.of(element.dataset.country) || element.dataset.country;
});
