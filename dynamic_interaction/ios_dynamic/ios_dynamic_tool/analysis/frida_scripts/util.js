function list_class_methods(className, filterString) {
	let methods = ObjC.classes[className].$ownMethods

	return methods.filter(methodName => {
		return (!filterString || methodName.indexOf(filterString) > -1)
	})
}
